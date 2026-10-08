from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "tooling" / "quality" / "security-exceptions.json"


def validate_bun_findings(
    findings: dict[str, list[dict[str, Any]]],
    exceptions: list[dict[str, Any]],
    *,
    today: date,
) -> list[str]:
    errors: list[str] = []
    observed: set[tuple[str, str]] = set()
    for package, advisories in findings.items():
        for advisory in advisories:
            url = advisory.get("url")
            if not isinstance(url, str):
                errors.append(f"{package}: advisory is missing its URL")
                continue
            observed.add((package, url))

    approved: set[tuple[str, str]] = set()
    for exception in exceptions:
        package = exception.get("package")
        advisory = exception.get("advisory")
        owner = exception.get("owner")
        reason = exception.get("reason")
        tracking_issue = exception.get("tracking_issue")
        expiry_text = exception.get("expires")
        if not all(isinstance(value, str) and value.strip() for value in (package, advisory, owner, reason)):
            errors.append("each Bun exception requires package, advisory, owner, and reason")
            continue
        if not isinstance(tracking_issue, int) or tracking_issue <= 0:
            errors.append(f"{package}: exception requires a positive tracking_issue")
            continue
        if not isinstance(expiry_text, str):
            errors.append(f"{package}: exception requires an expiry date")
            continue
        try:
            expiry = date.fromisoformat(expiry_text)
        except ValueError:
            errors.append(f"{package}: exception expiry must use YYYY-MM-DD")
            continue
        if expiry <= today:
            errors.append(f"{package}: exception expired on {expiry.isoformat()}")
            continue
        approved.add((package, advisory))

    for package, advisory in sorted(observed - approved):
        errors.append(f"unapproved Bun advisory: {package} {advisory}")
    for package, advisory in sorted(approved - observed):
        errors.append(f"stale Bun exception: remove {package} {advisory}")
    return errors


def main() -> int:
    completed = subprocess.run(
        ["bun", "audit", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    output = next((line for line in completed.stdout.splitlines() if line.lstrip().startswith("{")), None)
    if output is None:
        print("bun audit did not produce JSON output", file=sys.stderr)
        if completed.stderr:
            print(completed.stderr, file=sys.stderr)
        return completed.returncode or 1

    try:
        findings = json.loads(output)
        exceptions = json.loads(POLICY.read_text(encoding="utf-8"))["bun"]
    except (json.JSONDecodeError, KeyError, OSError) as error:
        print(f"could not read Bun audit policy: {error}", file=sys.stderr)
        return 1
    if not isinstance(findings, dict) or not isinstance(exceptions, list):
        print("Bun audit or security-exceptions.json has an invalid top-level shape", file=sys.stderr)
        return 1

    report_dir = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "bun-audit.json").write_text(
        json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    errors = validate_bun_findings(findings, exceptions, today=date.today())
    if errors:
        for error in errors:
            print(f"::error::{error}" if os.environ.get("GITHUB_ACTIONS") else error, file=sys.stderr)
        return 1

    print(f"Bun audit passed with {sum(map(len, findings.values()))} current advisory exception(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
