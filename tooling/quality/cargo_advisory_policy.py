from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "tooling" / "quality" / "security-exceptions.json"
DENY = ROOT / "deny.toml"


def validate_advisories(
    report: dict[str, Any],
    exceptions: list[dict[str, Any]],
    deny_ignored: list[str],
    *,
    today: date,
) -> list[str]:
    errors: list[str] = []
    vulnerabilities = report.get("vulnerabilities")
    findings = vulnerabilities.get("list") if isinstance(vulnerabilities, dict) else None
    if not isinstance(findings, list):
        return ["cargo audit report has no vulnerabilities.list array"]

    observed: set[str] = set()
    for finding in findings:
        advisory = finding.get("advisory") if isinstance(finding, dict) else None
        identifier = advisory.get("id") if isinstance(advisory, dict) else None
        if not isinstance(identifier, str) or not identifier:
            errors.append("cargo audit report contains a finding without an advisory ID")
        else:
            observed.add(identifier)

    approved: set[str] = set()
    for exception in exceptions:
        identifier = exception.get("advisory")
        owner = exception.get("owner")
        reason = exception.get("reason")
        tracking_issue = exception.get("tracking_issue")
        try:
            expiry = date.fromisoformat(exception.get("expires", ""))
        except (TypeError, ValueError):
            expiry = None
        if not isinstance(identifier, str) or not identifier:
            errors.append("Cargo advisory exception is missing an advisory ID")
            continue
        if identifier in approved:
            errors.append(f"duplicate Cargo advisory exception: {identifier}")
        if not isinstance(owner, str) or not owner.strip():
            errors.append(f"Cargo advisory exception {identifier} requires an owner")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"Cargo advisory exception {identifier} requires a reason")
        if not isinstance(tracking_issue, int) or tracking_issue <= 0:
            errors.append(f"Cargo advisory exception {identifier} requires a tracking_issue")
        if expiry is None:
            errors.append(f"Cargo advisory exception {identifier} requires an ISO expiry date")
        elif expiry <= today:
            errors.append(f"expired Cargo advisory exception: {identifier} expired {expiry}")
        approved.add(identifier)

    ignored = set(deny_ignored)
    if ignored != approved:
        errors.append("deny.toml advisory ignores must exactly match cargo_advisories exceptions")
    for identifier in sorted(observed - approved):
        errors.append(f"unapproved Cargo advisory: {identifier}")
    for identifier in sorted(approved - observed):
        errors.append(f"stale Cargo advisory exception: remove {identifier}")
    return errors


def main() -> int:
    try:
        exception_policy = json.loads(POLICY.read_text(encoding="utf-8"))
        deny_policy = tomllib.loads(DENY.read_text(encoding="utf-8"))
        exceptions = exception_policy["cargo_advisories"]
        deny_ignored = deny_policy["advisories"]["ignore"]
    except (KeyError, OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"could not read Cargo advisory policy: {error}", file=sys.stderr)
        return 1
    if not isinstance(exceptions, list) or any(not isinstance(item, dict) for item in exceptions):
        print("Cargo advisory exceptions must be a list of objects", file=sys.stderr)
        return 1
    if not isinstance(deny_ignored, list) or any(not isinstance(item, str) for item in deny_ignored):
        print("deny.toml advisory ignores must be a list of advisory IDs", file=sys.stderr)
        return 1

    completed = subprocess.run(
        ["cargo", "audit", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    report_dir = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "cargo-audit.json").write_text(completed.stdout, encoding="utf-8")
    if completed.returncode not in (0, 1):
        print(completed.stderr, file=sys.stderr)
        return completed.returncode
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        print(f"cargo audit did not produce JSON output: {error}", file=sys.stderr)
        return 1
    if not isinstance(report, dict):
        print("cargo audit report must be a JSON object", file=sys.stderr)
        return 1

    errors = validate_advisories(
        report, exceptions, deny_ignored, today=date.today()
    )
    if errors:
        for error in errors:
            print(f"::error::{error}" if os.environ.get("GITHUB_ACTIONS") else error, file=sys.stderr)
        return 1
    print("Cargo advisories comply with deny.toml and current scoped exceptions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
