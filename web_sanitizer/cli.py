"""Small CLI; no source values are printed, and source code is never executed."""

import argparse
import json
from pathlib import Path
import tempfile
import sys

from . import __version__
from .project import Failure, anonymize, restore, validate_config, write_json, inside


def load_config(path):
    if path is None:
        return {}
    try:
        with Path(path).open(encoding="utf-8") as stream:
            if Path(path).suffix.lower() in (".yaml", ".yml"):
                import yaml

                result = yaml.safe_load(stream)
            else:
                result = json.load(stream)
    except (OSError, ValueError):
        raise Failure("Cannot read configuration") from None
    validate_config(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Local reversible sanitization of complete web project folders. Never overwrites input."
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan", help="Analyze a project without creating a public working folder"
    )
    scan.add_argument("source", type=Path)
    scan.add_argument("--config", type=Path)
    scan.add_argument("--report", type=Path)
    create = sub.add_parser(
        "anonymize",
        help="Create a sanitized working folder and a separate private snapshot",
    )
    create.add_argument("source", type=Path)
    create.add_argument("output", type=Path)
    create.add_argument("--private", type=Path)
    create.add_argument("--config", type=Path)
    back = sub.add_parser("restore", help="Restore into a NEW complete project folder")
    back.add_argument("source", type=Path)
    back.add_argument("output", type=Path)
    back.add_argument("--private", type=Path)
    back.add_argument(
        "--allow-deleted",
        action="store_true",
        help="Accept intentional deletion/rename of working files",
    )
    back.add_argument(
        "--allow-missing",
        action="store_true",
        help="Accept intentionally removed placeholder occurrences",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "restore":
            report = restore(
                args.source,
                args.output,
                args.private,
                args.allow_deleted,
                args.allow_missing,
            )
            print(
                f"Restored {report['restored_tokens']} placeholder occurrences into a new folder."
            )
            if report["deleted_files"] or report["missing_tokens"]:
                print(
                    f"Accepted {len(report['deleted_files'])} deleted/renamed files and {len(report['missing_tokens'])} tokens with fewer occurrences."
                )
            print(
                "Run application tests before copying back. Quarantined files were restored unchanged."
            )
            return 0
        config = load_config(args.config)
        if args.command == "scan":
            destination = (
                args.report or Path(str(args.source.resolve()) + ".scan.json")
            ).resolve()
            if inside(destination, args.source.resolve()):
                raise Failure("Scan report must stay outside the source folder")
            if destination.exists():
                raise Failure("Report already exists; choose a new --report path")
            with tempfile.TemporaryDirectory(prefix="web-sanitizer-scan-") as temp:
                report = anonymize(args.source, Path(temp) / "working", config=config)
            write_json(destination, report)
            print(f"Local report: {destination}")
        else:
            if args.config and inside(args.config.resolve(), args.source.resolve()):
                raise Failure(
                    "Configuration with sensitive values must stay outside the source folder"
                )
            report = anonymize(args.source, args.output, args.private, config)
            print("Local report: <private folder>/report.json")
        print(
            f"Status: {report['status']}; included: {report['included']}; retained locally: {report['quarantined']}; replacements: {report['replacements']}."
        )
        print(
            "Share only the working folder. Never share the .private folder, mapping, scan report or configuration."
        )
        print(
            "A passed scan does not prove that all confidential information has been detected."
        )
        return 2 if report["status"] == "needs-review" else 0
    except Failure as error:
        print("Stopped: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except Exception:
        # Exception messages from parsers and files can contain secrets.
        print(
            "Stopped because of an unexpected local error. No exception details are printed to avoid disclosing sensitive values.",
            file=sys.stderr,
        )
        return 1
