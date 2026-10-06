from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")


def validate_packages(packages: list[dict[str, Any]], allowed: set[str]) -> list[str]:
    errors: list[str] = []
    for package in packages:
        if package.get("source") is None:
            continue  # First-party licensing is an owner decision; do not invent it.
        license_expression = package.get("license")
        name = f"{package.get('name')} {package.get('version')}"
        if not isinstance(license_expression, str) or not license_expression.strip():
            errors.append(f"third-party package has no declared license: {name}")
            continue

        tokens = TOKEN.findall(license_expression)
        unknown: list[str] = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in {"AND", "OR"}:
                index += 1
                continue
            if token == "WITH" and index > 0 and index + 1 < len(tokens):
                exception = f"{tokens[index - 1]} WITH {tokens[index + 1]}"
                if exception not in allowed:
                    unknown.append(exception)
                index += 2
                continue
            if token not in allowed and not (
                index + 1 < len(tokens) and tokens[index + 1] == "WITH"
            ):
                unknown.append(token)
            index += 1
        if unknown:
            errors.append(
                f"unapproved license token(s) for {name}: {', '.join(sorted(set(unknown)))}"
            )
    return errors


def main() -> int:
    policy = tomllib.loads((ROOT / "deny.toml").read_text(encoding="utf-8"))
    completed = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        print(completed.stderr, file=sys.stderr)
        return completed.returncode
    metadata = json.loads(completed.stdout)
    errors = validate_packages(metadata["packages"], set(policy["licenses"]["allow"]))
    report_dir = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "cargo-license-policy.json").write_text(
        json.dumps({"errors": errors}, indent=2) + "\n", encoding="utf-8"
    )
    if errors:
        for error in errors:
            print(f"::error::{error}" if "GITHUB_ACTIONS" in os.environ else error, file=sys.stderr)
        return 1
    print("Third-party Cargo licenses comply with deny.toml.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
