import json
from pathlib import Path
import pytest
from web_sanitizer.project import anonymize, restore, Failure


def setup(tmp_path, files):
    src = tmp_path / "original"
    src.mkdir()
    for name, data in files.items():
        p = src / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return src, tmp_path / "safe", tmp_path / "restored"


def tree(path):
    return {
        str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*") if p.is_file()
    }


def test_entire_folder_roundtrip(tmp_path):
    src, safe, out = setup(
        tmp_path,
        {
            "index.php": '<?php $password="abc";',
            "sub/x.js": 'const secret="abc";',
            ".env": "DB_PASS=abc\r\nPORT=3306\r\n",
            "pic/a.jpg": b"\xff\x00\xf0",
            "vendor/a.php": '<?php $password="vendor";',
        },
    )
    before = tree(src)
    report = anonymize(src, safe)
    assert report["status"] == "checks-passed"
    assert not (safe / "pic/a.jpg").exists()
    assert not (safe / "vendor/a.php").exists()
    assert "abc" not in (safe / "index.php").read_text()
    assert tree(src) == before
    restore(safe, out)
    assert tree(out) == before


def test_rename_and_cross_format_escape(tmp_path):
    src, safe, out = setup(tmp_path, {"config.php": r"""<?php $password='a"b\\c';"""})
    anonymize(src, safe)
    mapping = json.loads((Path(str(safe) + ".private") / "mapping.json").read_text())
    token = next(iter(mapping["tokens"]))
    (safe / "config.php").unlink()
    (safe / "config.json").write_text(json.dumps({"password": token}))
    restore(safe, out, allow_deleted=True)
    assert json.loads((out / "config.json").read_text())["password"] == 'a"b\\c'


def test_missing_token_blocks(tmp_path):
    src, safe, out = setup(tmp_path, {"x.php": '<?php $password="abc";'})
    anonymize(src, safe)
    (safe / "x.php").write_text('<?php $password="new";')
    with pytest.raises(Failure, match="missing"):
        restore(safe, out)
    assert not out.exists()


def test_existing_output_never_overwritten(tmp_path):
    src, safe, out = setup(tmp_path, {"x.js": 'const secret="abc";'})
    safe.mkdir()
    (safe / "keep").write_text("keep")
    with pytest.raises(Failure):
        anonymize(src, safe)
    assert (safe / "keep").read_text() == "keep"


def test_nested_output_refused(tmp_path):
    src, safe, out = setup(tmp_path, {})
    with pytest.raises(Failure):
        anonymize(src, src / "safe")


def test_symlinks_refused(tmp_path):
    src, safe, out = setup(tmp_path, {"a.txt": "abc"})
    (src / "b.txt").symlink_to(src / "a.txt")
    with pytest.raises(Failure):
        anonymize(src, safe)


def test_bad_syntax_quarantined(tmp_path):
    src, safe, out = setup(tmp_path, {"a.js": 'const password = "leak" + ;'})
    report = anonymize(src, safe)
    assert report["status"] == "needs-review"
    assert not (safe / "a.js").exists()
    restore(safe, out)
    assert tree(out) == tree(src)


def test_legacy_encoding_and_crlf(tmp_path):
    src, safe, out = setup(
        tmp_path,
        {"a.php": '<?php // Café\r\n$password="secret";\r\n'.encode("cp1252")},
    )
    anonymize(src, safe)
    restore(safe, out)
    assert tree(out) == tree(src)


def test_new_file_preserved(tmp_path):
    src, safe, out = setup(tmp_path, {"x.js": 'const secret="abc";'})
    anonymize(src, safe)
    (safe / "new.js").write_text("const added=42;")
    restore(safe, out)
    assert (out / "new.js").read_text() == "const added=42;"


def test_tampered_backup_blocks(tmp_path):
    src, safe, out = setup(tmp_path, {"x.js": 'const secret="abc";'})
    anonymize(src, safe)
    backup = next((Path(str(safe) + ".private") / "originals").iterdir())
    backup.write_bytes(b"tampered")
    with pytest.raises(Failure):
        restore(safe, out)


def test_unknown_placeholder_blocks(tmp_path):
    src, safe, out = setup(tmp_path, {"x.js": 'const secret="abc";'})
    anonymize(src, safe)
    with (safe / "x.js").open("a") as f:
        f.write("\n// WSP_FAKE_000001_END")
    with pytest.raises(Failure):
        restore(safe, out)


def test_unsupported_config_never_copied_unchecked(tmp_path):
    src, safe, out = setup(
        tmp_path, {"x.yaml": "password: abc\n", "x.xml": "<password>abc</password>"}
    )
    anonymize(src, safe)
    assert not (safe / "x.yaml").exists()
    assert not (safe / "x.xml").exists()
    restore(safe, out)
    assert tree(out) == tree(src)


def test_template_placeholders_inside_strings_restored(tmp_path):
    src, safe, out = setup(tmp_path, {"x.js": 'const secret="abc";'})
    anonymize(src, safe)
    token = next(
        iter(
            json.loads((Path(str(safe) + ".private") / "mapping.json").read_text())[
                "tokens"
            ]
        )
    )
    (safe / "x.js").write_text('const secret="prefix-' + token + '";')
    restore(safe, out)
    assert (out / "x.js").read_text() == 'const secret="prefix-abc";'


def test_all_values_custom_extension(tmp_path):
    src, safe, out = setup(tmp_path, {"settings.conf": "HOST=database\nPORT=1234\n"})
    anonymize(src, safe, config={"all_values": {"*.conf": "env"}})
    assert "database" not in (safe / "settings.conf").read_text()
    restore(safe, out)
    assert tree(out) == tree(src)


def test_deleted_duplicate_occurrence_blocks(tmp_path):
    src, safe, out = setup(
        tmp_path, {"x.js": 'const password="abc"; const secret="abc";'}
    )
    anonymize(src, safe)
    data = (safe / "x.js").read_text().split(";")[0] + ";"
    (safe / "x.js").write_text(data)
    with pytest.raises(Failure, match="missing"):
        restore(safe, out)


def test_known_sensitive_identifier_blocks_export(tmp_path):
    src, safe, out = setup(
        tmp_path,
        {
            "x.js": 'const secret="ConfidentialDepartment"; function ConfidentialDepartment() {}'
        },
    )
    report = anonymize(src, safe)
    assert report["status"] == "needs-review"
    assert not (safe / "x.js").exists()


def test_plain_restore_cannot_inject_comment_terminator(tmp_path):
    src, safe, out = setup(tmp_path, {"x.php": """<?php $password='*/ dangerous';"""})
    anonymize(src, safe)
    token = next(
        iter(
            json.loads((Path(str(safe) + ".private") / "mapping.json").read_text())[
                "tokens"
            ]
        )
    )
    (safe / "x.php").write_text("<?php /* " + token + " */")
    with pytest.raises(Failure):
        restore(safe, out)


def test_html_quote_change_preserves_attribute_value(tmp_path):
    from html import unescape

    src, safe, out = setup(
        tmp_path, {"x.html": '<div data-secret="a b\'c">Hello</div>'}
    )
    anonymize(src, safe)
    token = next(
        iter(
            json.loads((Path(str(safe) + ".private") / "mapping.json").read_text())[
                "tokens"
            ]
        )
    )
    (safe / "x.html").write_text("<div data-secret=" + token + ">Hello</div>")
    restore(safe, out)
    rendered = (out / "x.html").read_text()
    value = rendered.split("data-secret=")[1].split(">")[0]
    assert " " not in value
    assert unescape(value) == "a b'c"


def test_placeholder_can_move_to_html_text(tmp_path):
    src, safe, out = setup(
        tmp_path, {"x.html": '<div data-secret="a &lt; b">Hello</div>'}
    )
    anonymize(src, safe)
    token = next(
        iter(
            json.loads((Path(str(safe) + ".private") / "mapping.json").read_text())[
                "tokens"
            ]
        )
    )
    (safe / "x.html").write_text("<p>" + token + "</p>")
    restore(safe, out)
    assert (out / "x.html").read_text() == "<p>a &lt; b</p>"


def test_utf16_retained_locally_without_changes(tmp_path):
    src, safe, out = setup(
        tmp_path, {"x.php": '<?php $password="abc";'.encode("utf-16")}
    )
    report = anonymize(src, safe)
    assert report["status"] == "needs-review"
    assert not list(safe.iterdir())
    restore(safe, out)
    assert tree(src) == tree(out)
