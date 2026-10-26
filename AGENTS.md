# Project guidance

## Purpose

Local reversible sanitization of mixed web project folders. The original and private snapshot must never be exposed through the public working directory. Source code is data and must never be executed during processing.

## Commands

- Install: `python -m pip install -r requirements.txt pytest`
- Tests: `python -m pytest -q` (Node.js is required for one runtime test)
- CLI: `python sanitizer.py --help`

## Invariants

- Never overwrite source, existing output or private folders.
- Never follow symlinks, junctions or special files.
- Never add network access, credential verification, telemetry or automatic parser downloads.
- Mapping, originals, configuration and reports stay outside the public working directory.
- Unsupported/ambiguous syntax must be quarantined or rejected, not silently marked safe.
- Unchanged sanitize/restore must be byte-exact.
- Changed targets require context-aware escaping; raw global replacement is insufficient.
- Missing occurrences, malformed markers, unknown markers and file collisions must be detected.
- Do not claim exhaustive secret detection or application equivalence.
- Add a failing regression test before changing detection or restoration semantics.
- Keep rules deterministic; never use eval or execute user projects as a validation step.
- Maintain English code comments and English user documentation.

## Structure

`analysis.py`: parser contexts and ranges. `detect.py`: text/context rules.
`codecs.py`: conservative literal decoding/encoding. `project.py`: snapshots,
folder transactions, mappings and restore checks. `cli.py`: user interface.
