# Web Project Secret Sanitizer

Local, reversible pseudonymization of complete web project folders. Version 0.1.0.

**Original folder → sanitized working copy → editing → restored complete project.**

The original folder is never modified. Restoration also writes exclusively to a new folder. No configuration file is required for the default workflow. The tool does not execute project code or contact external services during processing.

## Windows quick start

Requires Python 3.12 or newer. With Python 3.12 installed, download this repository using **Code → Download ZIP**, extract it, open a command prompt in the extracted folder, and run:

```bat
install.cmd
```

Installation downloads pinned parser packages from PyPI. Processing works offline afterward. Administrator privileges are not required if Python is already available.

For another Python version starting with 3.12:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install --only-binary=:all: -r requirements.txt
```

### 1. Create the working copy

```bat
sanitizer.cmd anonymize "C:\Projects\Original" "C:\Projects\WorkingCopy"
```

| Folder | Contents | Share externally? |
|---|---|---|
| `Original` | Unmodified project | No |
| `WorkingCopy` | Sanitized supported files | Only after reviewing the local report |
| `WorkingCopy.private` | Complete original snapshot, plaintext mapping, and report | **Never** |

**Open only `WorkingCopy` in your coding assistant, not its parent directory.** When uploading files, select only files from that working folder. Keep configuration and reports local too: filenames can themselves contain confidential information.

### 2. Review the report and edit the working copy

`WorkingCopy.private/report.json` records the action for each file, including line numbers and review reasons where applicable. Detected values are not copied into the report. Console output contains summaries only.

- `checks-passed`: The implemented checks found no blocking issue. This is **not proof that all confidential information has been removed**.
- `needs-review`: At least one file was withheld because of an unresolved issue. That file is **absent** from the working copy. Resolve the report findings, then generate a new working copy.
- Binary files, archives, dependency directories, and excluded files remain in the private snapshot by default. They are restored unchanged later.

The working copy contains placeholders such as `WSP_7fd82e105a23_000001_END`. Keep these strings exactly intact when editing. Files may be renamed or split, and values may move between supported formats. Do not translate, shorten, invent, encode, or turn placeholders into variable names.

### 3. Restore a complete project

```bat
sanitizer.cmd restore "C:\Projects\WorkingCopy" "C:\Projects\Migrated"
```

The tool restores placeholders using the destination syntax context and adds locally retained files. The original folder remains untouched. Run application tests, compare the changes, and copy the reviewed result back yourself.

For intentionally renamed or deleted files:

```bat
sanitizer.cmd restore "C:\Projects\WorkingCopy" "C:\Projects\Migrated" --allow-deleted
```

If placeholder occurrences were also intentionally removed:

```bat
sanitizer.cmd restore "C:\Projects\WorkingCopy" "C:\Projects\Migrated" --allow-deleted --allow-missing
```

These options are explicit exceptions. Losing even one occurrence of a repeated placeholder is reported by default. Damaged and unknown placeholders remain errors. A new file cannot overwrite a locally retained original.

## Scan without creating a working copy

```bat
sanitizer.cmd scan "C:\Projects\Original"
```

Writes `C:\Projects\Original.scan.json`. Existing reports are never overwritten; use `--report` to select a different location outside the project folder. Scanning uses the same pipeline as anonymization, including a temporary local snapshot, so it temporarily needs roughly one additional project copy of disk space.

## Linux installation and usage

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: -r requirements.txt
.venv/bin/python sanitizer.py anonymize /projects/original /projects/working-copy
.venv/bin/python sanitizer.py restore /projects/working-copy /projects/migrated
```

Alternatively, run `pip install .` inside a virtual environment to install the `web-sanitizer` command.

## Try the included demo

From the repository directory on Windows:

```bat
sanitizer.cmd anonymize "examples\demo" "..\demo-working"
sanitizer.cmd restore "..\demo-working" "..\demo-restored"
```

The demo uses fictional values. The original and restored files should be byte-identical if the working copy was not edited. Choose fresh output folder names for another run.

## Format support

| Format | Processing |
|---|---|
| PHP, PHTML, INC | Tree-sitter: assignments, constants, arrays, class properties, selected function arguments, and simple unambiguous variable references |
| JavaScript, JSX, MJS, CJS, TypeScript, TSX | Tree-sitter: variables, objects, properties, string literals, and selected calls |
| HTML, HTM | Attributes, sensitive form values and metadata, text, comments, and embedded JavaScript, JSON, and CSS |
| PHP mixed with HTML | Static HTML regions receive additional analysis; complex nested templates may require review |
| CSS | URL/text patterns and string literals; no complete CSS escape support |
| JSON | String values and key context; keys are not blindly renamed |
| `.env`, `.env.*`, INI | All nonempty values; comments are scanned separately |
| TXT, Markdown, RST | Text patterns and labelled sensitive values |
| XML, SVG, YAML, TOML, and unknown configuration formats | Retained locally and reported for review by default; no implied syntax support |
| Images, PDFs, binary files, and unknown extensions | Retained locally; no OCR, image sanitization, or document sanitization |

Dependency directories (`vendor`, `node_modules`), version-control metadata, virtual Python environments, logs, backups, database files, SQL files, source maps, keys, and certificates are retained locally as well. They are restored unchanged and are unavailable for editing in the working copy.

Original empty directories are recreated during restoration. File contents are preserved byte-for-byte when the sanitized file remains unchanged. Supported encodings are UTF-8, UTF-8 with BOM, and Windows-1252 as a fallback, including CRLF line endings. UTF-16 and ambiguous formats are withheld. Ownership, Windows ACLs, timestamps, alternate data streams, and other special filesystem metadata are not fully backed up. Symbolic links and junctions are rejected.

## Detection

Built-in rules combine syntax context, text patterns, and checks for unusually random strings:

- Passwords, secrets, tokens, API keys, usernames, hosts, database names, DSNs, authentication, contact details, and selected personal data based on key or variable names.
- `define`, `PDO`, `mysqli`, `mysql_connect`, `pg_connect`, selected `curl_setopt` options, and setters.
- Email addresses, IPv4/IPv6, URLs including public URLs, internal domain suffixes, UNC paths, and user-directory paths.
- Patterns covering selected GitHub, GitLab, AWS access-key IDs, Google API keys, Slack, OpenAI-/Anthropic-style keys, Stripe, npm, PyPI, SendGrid, Docker Hub, Hugging Face, DigitalOcean, Linear, Vault, New Relic, and Supabase formats. Credentials are **never validated against a service**.
- JWTs, Basic/Bearer authorization headers, and PEM/PGP private-key blocks.
- International telephone-number patterns, IBAN patterns, and payment-card numbers with Luhn validation. False positives are possible; IBAN country lengths and checksums are not fully validated.
- Propagation of detected values to other files. Short values are matched at word boundaries. Matching structural keys and identifiers are flagged for review rather than blindly renamed.
- Review findings for dynamic or composite sensitive expressions, unsupported escapes, high entropy, serialized credentials, and selected decoding or code-execution calls.

Equal decoded values receive the same project-wide placeholder. Sensitive string literals are often replaced in full. This protects embedded values but can remove useful migration context such as URL paths or composite text. Comments are changed only at detected spans.

## Optional custom rules

The example configuration contains empty extension lists. Store your own configuration outside the project folder and pass it using `--config`:

```yaml
sensitive_keys:
  - customer_identifier
  - case_worker
sensitive_values:
  - InternalProjectName
  - DatabaseServer17
  - Jane Example
patterns:
  - '\bDEPT-[0-9]{6}\b'
all_values:
  '*.properties': properties
  'service.conf': ini
  'credentials.settings': env
exclude:
  - 'legacy-data/**'
max_file_bytes: 8388608
```

```bat
sanitizer.cmd anonymize "C:\Original" "C:\WorkingCopy" --config "C:\Private\rules.yaml"
```

`all_values` maps filename patterns to an existing adapter. Assigning an arbitrary extension does **not** automatically make its syntax understandable: `ini` expects INI-style key/value syntax, and `env` expects ENV-style assignments. `properties` supports simple single-line `key=value` or `key:value` files, not the entire Java Properties specification. Multiline values and continuations are handled conservatively. Custom regular expressions are trusted local configuration; complex patterns may be slow.

Lists extend built-in rules. Configuration is never automatically loaded from the project being analyzed. If the working folder and private snapshot are not adjacent, pass `--private "C:\Private\Snapshot"` when anonymizing and restoring. Source, output, and private folders must not be nested within one another.

## Safety and functional limits

**This is a tested tool with bounded detection rules, not a guarantee that every confidential detail has been removed.** Free-form personal names, organization-specific terms, confidential business logic, unusual server names, encrypted/encoded or dynamically generated secrets, and unknown token formats may remain undetected. Additional local rules and report review are still necessary.

The sanitized copy is intended for editing. Replaced credentials, ports, and other values, together with withheld files, mean it is not necessarily runnable. Preserving syntax does not establish functional equivalence. Tree-sitter is not a PHP interpreter or a complete language compiler. Test the restored application using its actual runtimes and project-specific tests before deployment.

Restoration across syntax contexts is supported only where the destination is understood. Unchanged files are retrieved directly from the verified snapshot. Changed files are analyzed again; supported escaping contexts are converted, and unsupported cases are rejected. Do not edit the source folder concurrently while generating a working copy. This tool does not replace a backup.

The private snapshot contains **the entire original project and all original files**, not just a substitution table. It is unencrypted. Configure appropriate folder permissions yourself on shared Windows computers. Scanning also creates temporary original copies; normal deletion does not guarantee secure erasure from storage.

## Development and testing

```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
```

One runtime test requires Node.js; it is **not a runtime dependency of the sanitizer**. All other tests need only Python and the listed packages. Parser packages contain their grammars locally; scans do not download additional parsers.

Tests cover folder round trips, codecs, new/renamed/deleted files, missing and unknown placeholders, binary files, legacy encodings, configuration adapters, directory separation, modified backups, symlinks, CLI exit codes, offline processing, and a format migration followed by JavaScript execution. See [TESTING.md](TESTING.md) for the verification record and [AGENTS.md](AGENTS.md) for contributor guidance.

Exit codes: `0` success, `2` review required for a completed scan/anonymization, `1` failure, `130` cancellation. With `needs-review`, a partial sanitized working folder exists; it does not remove the need to review the report.

## Technical references

- [Tree-sitter Python bindings](https://github.com/tree-sitter/py-tree-sitter)
- [PHP grammar](https://github.com/tree-sitter/tree-sitter-php)
- [JavaScript grammar](https://github.com/tree-sitter/tree-sitter-javascript)

No Gitleaks rule catalog is bundled. The integrated rules are a separate, limited set and do not replace its full catalog.
