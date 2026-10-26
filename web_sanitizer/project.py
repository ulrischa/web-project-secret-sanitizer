"""Non-destructive folder transactions and private, reversible mappings."""

import collections
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import uuid

from .analysis import analyze, LANGUAGES, config_format
from .codecs import Unsafe, encode_value
from .detect import detect

TOKEN = re.compile(r"WSP_[A-Za-z0-9_]+_END")
EXCLUDED_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "logs",
    "backups",
    ".idea",
    ".vscode",
}
TEXT_EXTENSIONS = set(LANGUAGES) | {
    ".txt",
    ".md",
    ".rst",
    ".svg",
    ".xml",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".properties",
    ".conf",
    ".config",
    ".htaccess",
    ".htpasswd",
}
MAX_BYTES = 8 * 1024 * 1024


class Failure(ValueError):
    """Errors intentionally omit secret content and untrusted exception messages."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, data):
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    path.chmod(0o600)


def read_text(data):
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        raise Failure("UTF-16 requires explicit conversion before processing")
    if b"\x00" in data:
        raise Failure("binary-content")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig"), "utf-8-sig"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        try:
            return data.decode("cp1252"), "cp1252"
        except UnicodeDecodeError:
            raise Failure("unsupported-encoding") from None


def inside(child, parent):
    return child == parent or parent in child.parents


def disjoint(*paths):
    for i, a in enumerate(paths):
        for b in paths[i + 1 :]:
            if inside(a, b) or inside(b, a):
                raise Failure(
                    "Source, output and private folder must be separate, non-nested directories"
                )


def inventory(root):
    files = []
    directories = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        names.sort()
        for name in dirs + names:
            p = Path(current) / name
            mode = p.lstat().st_mode
            if p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()):
                raise Failure("Symlink or junction found; no links are followed")
            if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
                raise Failure("Special filesystem entry found")
        directories.extend(
            (Path(current) / d).relative_to(root).as_posix() for d in dirs
        )
        files.extend((Path(current) / n).relative_to(root).as_posix() for n in names)
    return files, directories


def safe_relative(value):
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or any(x in (".", "..") for x in path.parts)
        or "\\" in value
        or ":" in value
    ):
        raise Failure("Invalid path in private manifest")
    return path


def is_excluded(name, config):
    p = PurePosixPath(name)
    return (
        any(x in EXCLUDED_DIRS for x in p.parts[:-1])
        or any(fnmatch.fnmatch(name, g) for g in config.get("exclude", []))
        or p.suffix.lower()
        in {
            ".log",
            ".sql",
            ".bak",
            ".backup",
            ".old",
            ".map",
            ".zip",
            ".gz",
            ".tar",
            ".sqlite",
            ".db",
            ".pem",
            ".key",
            ".pfx",
            ".p12",
            ".crt",
        }
    )


def expected_text(name, config):
    return (
        Path(name).suffix.lower() in TEXT_EXTENSIONS
        or Path(name).name in {".htaccess", ".htpasswd"}
        or bool(config_format(name, config))
    )


def validate_config(config):
    allowed = {
        "exclude",
        "all_values",
        "sensitive_keys",
        "sensitive_values",
        "patterns",
        "max_file_bytes",
    }
    if not isinstance(config, dict) or set(config) - allowed:
        raise Failure("Unknown configuration option")
    for key in ("exclude", "sensitive_keys", "sensitive_values", "patterns"):
        if key in config and (
            not isinstance(config[key], list)
            or not all(isinstance(v, str) and v for v in config[key])
        ):
            raise Failure("Configuration lists require non-empty strings")
    adapters = config.get("all_values", {})
    if not isinstance(adapters, dict) or any(
        not isinstance(k, str) or v not in ("env", "ini", "properties")
        for k, v in adapters.items()
    ):
        raise Failure("all_values maps file patterns to env, ini or properties")
    if (
        type(config.get("max_file_bytes", MAX_BYTES)) is not int
        or config.get("max_file_bytes", MAX_BYTES) < 1
    ):
        raise Failure("Invalid max_file_bytes")
    for pattern in config.get("patterns", []):
        try:
            compiled = re.compile(pattern)
            if compiled.match(""):
                raise Failure("Custom patterns must not match empty strings")
        except re.error:
            raise Failure("Invalid custom pattern") from None


def anonymize(source, output, private=None, config=None):
    source = Path(source).resolve()
    output = Path(output).resolve()
    private = Path(private).resolve() if private else Path(str(output) + ".private")
    config = config or {}
    validate_config(config)
    disjoint(source, output, private)
    if not source.is_dir():
        raise Failure("Source directory does not exist")
    if output.exists() or private.exists():
        raise Failure("Output/private directory already exists; choose new names")
    files, directories = inventory(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    private.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".sanitizer-", dir=output.parent))
    vault = Path(tempfile.mkdtemp(prefix=".sanitizer-private-", dir=private.parent))
    vault.chmod(0o700)
    (vault / "originals").mkdir(mode=0o700)
    manifest = {
        "version": 1,
        "run": uuid.uuid4().hex[:12],
        "tokens": {},
        "files": {},
        "directories": directories,
        "config": config,
    }
    report = {
        "status": "checks-passed",
        "included": 0,
        "quarantined": 0,
        "replacements": 0,
        "files": [],
    }
    known = set(config.get("sensitive_values", []))
    try:
        # Snapshot first: all later reads use the immutable local snapshot.
        for i, name in enumerate(files):
            origin = source / name
            backup = vault / "originals" / f"{i:08d}"
            shutil.copyfile(origin, backup)
            backup.chmod(0o600)
            meta = {
                "backup": backup.name,
                "sha256": file_digest(backup),
                "mode": stat.S_IMODE(origin.stat().st_mode),
                "included": False,
            }
            manifest["files"][name] = meta
            info = {
                "path": name,
                "issues": [],
                "replacements": 0,
                "action": "quarantined",
            }
            report["files"].append(info)
            if is_excluded(name, config):
                info["reason"] = "excluded"
                continue
            if not expected_text(name, config):
                info["reason"] = "non-source-file"
                continue
            if Path(name).suffix.lower() in {
                ".yaml",
                ".yml",
                ".xml",
                ".svg",
                ".toml",
                ".conf",
                ".config",
                ".properties",
            } or Path(name).name in {".htaccess", ".htpasswd"}:
                if not config_format(name, config):
                    info["issues"] = [
                        {"line": 0, "reason": "unsupported-format-review"}
                    ]
                    continue
            if backup.stat().st_size > config.get("max_file_bytes", MAX_BYTES):
                info["issues"] = [{"line": 0, "reason": "file-too-large"}]
                continue
            try:
                text, encoding = read_text(backup.read_bytes())
            except Failure:
                info["issues"] = [
                    {"line": 0, "reason": "unsupported-encoding-or-binary"}
                ]
                continue
            if "WSP_" in text:
                raise Failure("Source already contains reserved WSP_ markers")
            meta["encoding"] = encoding
            first = analyze(name, text, config)
            known.update(
                r.value
                for r in first.edits
                if r.reason != "config-value"
                or (
                    len(r.value) >= 4
                    and not r.value.isdecimal()
                    and r.value.lower() not in {"true", "false", "null", "none"}
                )
            )
        # Propagate detected literals into other supported contexts without editing identifiers.
        # Short values use exact-string propagation only in analysis.
        token_by_value = {}
        for info in report["files"]:
            name = info["path"]
            meta = manifest["files"][name]
            if "encoding" not in meta:
                continue
            text = (
                (vault / "originals" / meta["backup"])
                .read_bytes()
                .decode(meta["encoding"])
            )
            if detect(name, known, config.get("patterns", [])):
                info["issues"] = [{"line": 0, "reason": "sensitive-path-review"}]
                continue
            result = analyze(name, text, config, known)
            info["issues"] = result.issues
            if result.issues:
                continue
            edited = text
            occurrences = []
            for r in reversed(result.edits):
                token = token_by_value.get(r.value)
                if token is None:
                    token = f"WSP_{manifest['run']}_{len(token_by_value) + 1:06d}_END"
                    token_by_value[r.value] = token
                    manifest["tokens"][token] = {"value": r.value, "occurrences": []}
                raw = text[r.start : r.end]
                manifest["tokens"][token]["occurrences"].append(
                    {"path": name, "codec": r.codec, "raw": raw}
                )
                occurrences.append(token)
                edited = edited[: r.start] + token + edited[r.end :]
            # Roundtrip is checked before publishing any file.
            reversed_text = edited
            raw_by_token = {}
            for r in result.edits:
                raw_by_token.setdefault(token_by_value[r.value], []).append(
                    text[r.start : r.end]
                )
            cursors = collections.Counter()

            def undo(m):
                token = m.group()
                index = cursors[token]
                cursors[token] += 1
                return raw_by_token[token][index]

            reversed_text = TOKEN.sub(undo, reversed_text)
            if (
                reversed_text.encode(meta["encoding"])
                != (vault / "originals" / meta["backup"]).read_bytes()
            ):
                raise Failure("Internal roundtrip verification failed")
            # Reparse and scan the entire generated file; neutralize markers for entropy checks.
            neutral = TOKEN.sub("sanitized", edited)
            check = analyze(name, neutral, config)
            source_issues = [x for x in check.issues if "syntax" in x["reason"]]
            if source_issues:
                raise Failure("Generated source failed syntax validation")
            residual = detect(
                TOKEN.sub("", edited),
                config.get("sensitive_values", []),
                config.get("patterns", []),
            )
            if residual:
                info["issues"] = [{"line": 0, "reason": "residual-sensitive-content"}]
                # Do not retain tokens whose only appearances were in a quarantined file.
                for token in occurrences:
                    manifest["tokens"][token]["occurrences"] = [
                        o
                        for o in manifest["tokens"][token]["occurrences"]
                        if o["path"] != name
                    ]
                continue
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            data = edited.encode(meta["encoding"])
            target.write_bytes(data)
            target.chmod(meta["mode"] & 0o777)
            meta.update(included=True, safe_sha256=digest(data), tokens=occurrences)
            info.update(action="included", replacements=len(result.edits))
        manifest["tokens"] = {
            t: v for t, v in manifest["tokens"].items() if v["occurrences"]
        }
        for info in report["files"]:
            report["included" if info["action"] == "included" else "quarantined"] += 1
            report["replacements"] += info["replacements"]
            if info["issues"]:
                report["status"] = "needs-review"
        manifest["report_status"] = report["status"]
        write_json(vault / "mapping.json", manifest)
        write_json(vault / "report.json", report)
        vault.rename(private)
        staging.rename(output)
        return report
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(vault, ignore_errors=True)
        raise


def restore(source, output, private=None, allow_deleted=False, allow_missing=False):
    source = Path(source).resolve()
    output = Path(output).resolve()
    private = Path(private).resolve() if private else Path(str(source) + ".private")
    disjoint(source, output, private)
    if not source.is_dir() or not private.is_dir():
        raise Failure("Working/private folder missing")
    if output.exists():
        raise Failure("Output already exists; nothing overwritten")
    inventory(private)
    try:
        manifest = json.loads((private / "mapping.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Failure("Cannot read private mapping") from None
    if manifest.get("version") != 1:
        raise Failure("Unsupported mapping version")
    files, directories = inventory(source)
    metadata = manifest["files"]
    tokens = manifest["tokens"]
    seen = collections.Counter()
    format_config = {"all_values": manifest.get("config", {}).get("all_values", {})}
    validate_config(format_config)
    for name, meta in metadata.items():
        safe_relative(name)
        if not re.fullmatch(r"\d{8}", meta["backup"]):
            raise Failure("Invalid backup identifier")
        backup = private / "originals" / meta["backup"]
        if not backup.is_file() or file_digest(backup) != meta["sha256"]:
            raise Failure("Original backup integrity check failed")
    for token, entry in tokens.items():
        if not TOKEN.fullmatch(token) or not isinstance(entry.get("value"), str):
            raise Failure("Invalid token mapping")
    absent = [n for n, m in metadata.items() if m["included"] and n not in files]
    if absent and not allow_deleted:
        raise Failure(
            "Original working files missing or renamed; use --allow-deleted after review"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".restore-", dir=output.parent))
    try:
        for name in files:
            origin = source / name
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            meta = metadata.get(name)
            if meta and not meta["included"]:
                raise Failure("New file conflicts with a quarantined original")
            data = origin.read_bytes()
            if meta and digest(data) == meta["safe_sha256"]:
                shutil.copyfile(private / "originals" / meta["backup"], target)
                seen.update(meta["tokens"])
                target.chmod(meta["mode"] & 0o777)
                continue
            try:
                text, encoding = read_text(data)
            except Failure:
                if (
                    expected_text(name, format_config)
                    or b"WSP_" in data
                    or b"W\x00S\x00P\x00_" in data
                ):
                    raise Failure(
                        "Edited text has unsupported encoding, or binary file contains a marker"
                    )
                target.write_bytes(data)
                continue
            analysis = analyze(name, text, format_config)
            if any("syntax" in x["reason"] for x in analysis.issues):
                raise Failure("Edited source has syntax errors")
            edits = []
            for match in TOKEN.finditer(text):
                token = match.group()
                if token not in tokens:
                    raise Failure("Unknown placeholder found")
                entry = tokens[token]
                regions = [
                    r
                    for r in analysis.regions
                    if r.start <= match.start() and match.end() <= r.end
                ]
                region = (
                    min(regions, key=lambda r: r.end - r.start) if regions else None
                )
                if region is None and (
                    Path(name).suffix.lower() in LANGUAGES
                    or config_format(name, format_config)
                ):
                    # Comment/prose contexts can be restored only with same-format raw variants.
                    before = text[: match.start()].rsplit("\n", 1)[-1]
                    if not before.lstrip().startswith(
                        ("//", "#", ";", "/*", "*", "<!--")
                    ):
                        raise Failure("Placeholder moved outside a supported literal")
                codec = region.codec if region else "plain"
                variants = {
                    o["raw"] for o in entry["occurrences"] if o["codec"] == codec
                }
                if len(variants) == 1:
                    replacement = next(iter(variants))
                else:
                    try:
                        replacement = encode_value(entry["value"], codec)
                    except (Unsafe, ValueError):
                        raise Failure(
                            "Cannot safely escape value in new context"
                        ) from None
                # Unquoted config values must remain representable without changing grammar.
                if (
                    codec == "plain"
                    and config_format(name, format_config)
                    and any(c in replacement for c in "\r\n\x00#;$\"'")
                ):
                    raise Failure(
                        "Restored configuration value needs quotes; quote its placeholder first"
                    )
                edits.append((match.start(), match.end(), replacement))
                seen[token] += 1
            stripped = TOKEN.sub("", text)
            if "WSP_" in stripped:
                raise Failure("Damaged placeholder found")
            for a, b, replacement in reversed(edits):
                text = text[:a] + replacement + text[b:]
            check = analyze(name, text, format_config)
            if any("syntax" in x["reason"] for x in check.issues):
                raise Failure("Restored source failed syntax validation")
            try:
                target.write_bytes(text.encode(encoding))
            except UnicodeEncodeError:
                raise Failure("Restored value does not fit target encoding") from None
            target.chmod(stat.S_IMODE(origin.stat().st_mode) & 0o777)
        expected = collections.Counter()
        for meta in metadata.values():
            if meta["included"]:
                expected.update(meta["tokens"])
        missing = {t for t in tokens if seen[t] < expected[t]}
        if missing and not allow_missing:
            raise Failure(
                "Known placeholder occurrences missing: "
                + ", ".join(sorted(missing))
                + "; use --allow-missing after review"
            )
        for name, meta in metadata.items():
            if not meta["included"]:
                target = staging / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    raise Failure("Quarantined file conflicts with edited project")
                shutil.copyfile(private / "originals" / meta["backup"], target)
                target.chmod(meta["mode"] & 0o777)
        # Preserve original empty directories, including locally retained asset folders.
        for name in manifest.get("directories", []) + directories:
            safe_relative(name)
            target = staging / name
            if target.is_file():
                raise Failure("File/directory conflict")
            target.mkdir(parents=True, exist_ok=True)
        staging.rename(output)
        return {
            "status": "restored",
            "restored_tokens": sum(seen.values()),
            "missing_tokens": sorted(missing),
            "deleted_files": absent,
        }
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
