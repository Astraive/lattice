from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")


def validate_packages(
    packages: list[dict[str, Any]],
    allowed: set[str],
    exceptions: list[dict[str, Any]] | None = None,
    *,
    today: date | None = None,
) -> list[str]:
    errors: list[str] = []
    today = today or date.today()
    approved: set[tuple[str, str, str]] = set()
    for exception in exceptions or []:
        package = exception.get("package")
        version = exception.get("version")
        license_token = exception.get("license")
        owner = exception.get("owner")
        reason = exception.get("reason")
        tracking_issue = exception.get("tracking_issue")
        expiry_text = exception.get("expires")
        identity = f"{package} {version}"
        if not all(
            isinstance(value, str) and value.strip()
            for value in (package, version, license_token, owner, reason)
        ):
            errors.append(
                "each Cargo license exception requires package, version, license, owner, and reason"
            )
            continue
        if not isinstance(tracking_issue, int) or isinstance(tracking_issue, bool) or tracking_issue <= 0:
            errors.append(f"{identity}: exception requires a positive tracking_issue")
            continue
        if not isinstance(expiry_text, str):
            errors.append(f"{identity}: exception requires an expiry date")
            continue
        try:
            expiry = date.fromisoformat(expiry_text)
        except ValueError:
            errors.append(f"{identity}: exception expiry must use YYYY-MM-DD")
            continue
        if expiry <= today:
            errors.append(f"{identity}: exception expired on {expiry.isoformat()}")
            continue
        approved.add((package, version, license_token))

    observed_exceptions: set[tuple[str, str, str]] = set()
    for package in packages:
        if package.get("source") is None:
            continue  # First-party licensing is an owner decision; do not invent it.
        license_expression = package.get("license")
        name = str(package.get("name"))
        version = str(package.get("version"))
        identity = f"{name} {version}"
        if not isinstance(license_expression, str) or not license_expression.strip():
            errors.append(f"third-party package has no declared license: {identity}")
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
                exception_key = (name, version, token)
                observed_exceptions.add(exception_key)
                if exception_key not in approved:
                    unknown.append(token)
            index += 1
        if unknown:
            errors.append(
                f"unapproved license token(s) for {identity}: {', '.join(sorted(set(unknown)))}"
            )

    for package, version, license_token in sorted(approved - observed_exceptions):
        errors.append(
            f"stale Cargo license exception: remove {package} {version} {license_token}"
        )
    return errors


def main() -> int:
    try:
        policy = tomllib.loads((ROOT / "deny.toml").read_text(encoding="utf-8"))
        exception_policy = json.loads(
            (ROOT / "tooling" / "quality" / "security-exceptions.json").read_text(encoding="utf-8")
        )
        exceptions = exception_policy["cargo_licenses"]
    except (KeyError, OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"could not read Cargo license policy: {error}", file=sys.stderr)
        return 1
    if not isinstance(exceptions, list) or any(not isinstance(item, dict) for item in exceptions):
        print("Cargo license exceptions must be a list of objects", file=sys.stderr)
        return 1

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
    errors = validate_packages(
        metadata["packages"],
        set(policy["licenses"]["allow"]),
        exceptions,
        today=date.today(),
    )
    report_dir = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "cargo-license-policy.json").write_text(
        json.dumps({"errors": errors}, indent=2) + "\n", encoding="utf-8"
    )
    if errors:
        for error in errors:
            print(f"::error::{error}" if "GITHUB_ACTIONS" in os.environ else error, file=sys.stderr)
        return 1
    print("Third-party Cargo licenses comply with deny.toml and current scoped exceptions.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
