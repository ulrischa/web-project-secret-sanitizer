# Verification record for version 0.1.0

## Checks performed

- Python 3.12.14 on Linux.
- `python -m pytest -q`: **90 tests passed**, none skipped.
- `python -m ruff check . --select F`: no findings.
- `python -m compileall -q web_sanitizer`: successful.
- Python wheel built using setuptools: successful.
- CLI demo with PHP, JavaScript, and INI: 3 files, 8 substitutions, successful byte-for-byte round trip.
- A 500-file PHP fixture: successful sanitization and byte-for-byte restoration.
- JavaScript runtime test using Node: a password moved from JSON to a template string evaluates to exactly the original value after restoration.
- Offline test with Python socket connections blocked: sanitization and restoration succeeded.

## Covered risks

- Original-file protection, pre-existing output folders, and nested directories.
- Symbolic links, modified original snapshots, and conflicts with retained files.
- Unknown and missing placeholders, including loss of individual repeated occurrences.
- Renamed files, new files, format changes, and quotation changes.
- Unicode positions, Windows-1252, CRLF, and UTF-16 quarantine.
- PHP/JS/TS/JSON/HTML/CSS contexts, nested configuration, and PHP class properties.
- Comments, serialized data, dynamic expressions, and unsupported escape sequences.
- No plaintext passwords in console output or the sanitized demo.

## Not established by these local checks

- Practical operation on Windows. Startup scripts and a Windows/Linux CI matrix are included; the local verification record does not claim that those remote jobs have run. Consult the repository's Actions results for their current status.
- PHP interpreter validation: no PHP interpreter was available in the local environment. PHP syntax was analyzed using Tree-sitter.
- Complete detection across real confidential projects, arbitrary frameworks, and all secret formats.
- Unchanged runtime behavior after external code edits. That requires application-specific tests.
- An independent security audit.

This record describes concrete checks and does not constitute clearance to share confidential source code.
