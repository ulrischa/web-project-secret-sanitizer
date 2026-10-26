import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(*arguments):
    return subprocess.run(
        [sys.executable, str(ROOT / "sanitizer.py"), *map(str, arguments)],
        capture_output=True,
        text=True,
    )


def test_cli_scan_anonymize_restore(tmp_path):
    src = tmp_path / "input"
    src.mkdir()
    (src / "x.js").write_text('const password="abc";')
    scan = run("scan", src)
    assert scan.returncode == 0, scan.stderr
    assert "abc" not in scan.stdout + scan.stderr
    assert json.loads(Path(str(src) + ".scan.json").read_text())["replacements"] == 1
    safe = tmp_path / "working"
    final = tmp_path / "final"
    assert run("anonymize", src, safe).returncode == 0
    assert run("restore", safe, final).returncode == 0
    assert (final / "x.js").read_bytes() == (src / "x.js").read_bytes()


def test_cli_needs_review_exit_code(tmp_path):
    src = tmp_path / "input"
    src.mkdir()
    (src / "x.php").write_text("<?php $password = load_secret();")
    result = run("anonymize", src, tmp_path / "safe")
    assert result.returncode == 2
    assert "needs-review" in result.stdout


def test_mapping_never_appears_in_working_folder(tmp_path):
    src = tmp_path / "input"
    src.mkdir()
    (src / "x.json").write_text('{"password":"very_private"}')
    safe = tmp_path / "working"
    assert run("anonymize", src, safe).returncode == 0
    assert {p.name for p in safe.iterdir()} == {"x.json"}
    assert "very_private" not in (safe / "x.json").read_text()


def test_offline_processing(tmp_path, monkeypatch):
    import socket
    from web_sanitizer.project import anonymize, restore

    def deny(*args, **kwargs):
        raise AssertionError("Network access attempted")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    src = tmp_path / "input"
    src.mkdir()
    (src / "x.js").write_text('const password="abc";')
    safe = tmp_path / "working"
    anonymize(src, safe)
    restore(safe, tmp_path / "final")


def test_javascript_runtime_value_after_context_change(tmp_path):
    from web_sanitizer.project import anonymize, restore

    src = tmp_path / "input"
    src.mkdir()
    original = 'a"b\\c\n${value}'
    (src / "x.json").write_text(json.dumps({"password": original}))
    safe = tmp_path / "working"
    anonymize(src, safe)
    token = json.loads((safe / "x.json").read_text())["password"]
    (safe / "x.json").unlink()
    (safe / "x.js").write_text(
        "const password=`" + token + "`; console.log(JSON.stringify(password));"
    )
    final = tmp_path / "final"
    restore(safe, final, allow_deleted=True)
    result = subprocess.run(
        ["node", str(final / "x.js")], capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout) == original
