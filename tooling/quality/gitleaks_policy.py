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


def validate_findings(
    findings: list[dict[str, Any]], exceptions: list[dict[str, Any]], *, today: date
) -> list[str]:
    errors: list[str] = []
    observed = {finding.get("Fingerprint") for finding in findings}
    approved: set[str] = set()
    for exception in exceptions:
        fingerprint = exception.get("fingerprint")
        owner = exception.get("owner")
        reason = exception.get("reason")
        issue = exception.get("tracking_issue")
        try:
            expiry = date.fromisoformat(exception.get("expires", ""))
        except (TypeError, ValueError):
            expiry = None
        if not isinstance(fingerprint, str) or not fingerprint:
            errors.append("Gitleaks exception requires a fingerprint")
            continue
        if not isinstance(owner, str) or not owner.strip():
            errors.append(f"Gitleaks exception {fingerprint} requires an owner")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"Gitleaks exception {fingerprint} requires a reason")
        if not isinstance(issue, int) or issue <= 0:
            errors.append(f"Gitleaks exception {fingerprint} requires a tracking issue")
        if expiry is None or expiry <= today:
            errors.append(f"Gitleaks exception {fingerprint} requires a future expiry")
        if fingerprint in approved:
            errors.append(f"duplicate Gitleaks exception: {fingerprint}")
        approved.add(fingerprint)
    for fingerprint in sorted(observed - approved):
        errors.append(f"unapproved Gitleaks finding: {fingerprint}")
    for fingerprint in sorted(approved - observed):
        errors.append(f"stale Gitleaks exception: remove {fingerprint}")
    return errors


def main() -> int:
    report_dir = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    report_dir.mkdir(parents=True, exist_ok=True)
    raw_report = report_dir / "gitleaks-raw.json"
    completed = subprocess.run(
        [
            "gitleaks",
            "git",
            "--redact=100",
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            str(raw_report),
            ".",
        ],
        cwd=ROOT,
        check=False,
        text=True,
    )
    if completed.returncode not in (0, 1):
        print(f"gitleaks failed to scan repository (exit {completed.returncode})", file=sys.stderr)
        return completed.returncode
    try:
        findings = json.loads(raw_report.read_text(encoding="utf-8"))
        exceptions = json.loads(POLICY.read_text(encoding="utf-8"))["gitleaks"]
    except (json.JSONDecodeError, KeyError, OSError) as error:
        print(f"could not read Gitleaks report or exception policy: {error}", file=sys.stderr)
        return 1
    if not isinstance(findings, list) or not isinstance(exceptions, list):
        print("Gitleaks report or exception policy has an invalid shape", file=sys.stderr)
        return 1

    errors = validate_findings(findings, exceptions, today=date.today())
    safe_findings = []
    for finding in findings:
        safe = {
            key: value
            for key, value in finding.items()
            if key not in {"Author", "Email", "Message", "Secret", "Match"}
        }
        safe["Secret"] = "REDACTED"
        safe["Match"] = "REDACTED"
        safe["ApprovedException"] = finding.get("Fingerprint") in {
            exception.get("fingerprint") for exception in exceptions
        }
        safe_findings.append(safe)
    (report_dir / "gitleaks.json").write_text(
        json.dumps(safe_findings, indent=2) + "\n", encoding="utf-8"
    )
    if errors:
        for error in errors:
            print(f"::error::{error}" if os.environ.get("GITHUB_ACTIONS") else error, file=sys.stderr)
        return 1
    print(f"Gitleaks passed with {len(findings)} current exact exception(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
