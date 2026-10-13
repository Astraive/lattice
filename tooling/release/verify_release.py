from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

FUZZ_TARGETS = (
    "canonical",
    "identity-bundle",
    "signed-event",
    "relay-envelope",
    "nostr-event",
    "attachment-manifest",
    "sync-plan",
    "nip11",
    "path-upgrade",
    "ble-noise-ingress",
    "space-invite-bootstrap",
    "mls-credential",
    "voice-signaling-sequence",
)
EXPECTED_DEEP_JOBS = {
    "Migration, protocol, convergence, and reproducibility checks",
    *(f"Fuzz {target}" for target in FUZZ_TARGETS),
}


def validate_deep_jobs(jobs: list[dict[str, Any]]) -> list[str]:
    names = {job.get("name") for job in jobs}
    errors = []
    if names != EXPECTED_DEEP_JOBS:
        errors.append("Deep verification run must contain the deterministic job and all 13 fuzz targets")
    if any(
        job.get("status") != "completed" or job.get("conclusion") != "success"
        for job in jobs
    ):
        errors.append("Deep verification has failed, skipped, or incomplete jobs")
    return errors
ANDROID_VERSION = re.compile(r'^\s*versionName\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
ANDROID_VERSION_CODE = re.compile(r"^\s*versionCode\s*=\s*(\d+)\s*$", re.MULTILINE)


def android_version_code(version: str) -> int:
    match = SEMVER.fullmatch(f"v{version}")
    if match is None:
        raise ValueError("release version must be MAJOR.MINOR.PATCH")
    major, minor, patch = map(int, match.groups())
    if minor >= 1000 or patch >= 1000:
        raise ValueError("version components exceed Android versionCode encoding limits")
    code = major * 1_000_000 + minor * 1_000 + patch
    if code == 0 or code > 2_100_000_000:
        raise ValueError("release version exceeds Android's supported versionCode range")
    return code


def release_versions(root: Path = ROOT) -> dict[str, str]:
    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    root_package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    desktop_package = json.loads(
        (root / "apps/desktop/package.json").read_text(encoding="utf-8")
    )
    tauri = json.loads(
        (root / "apps/desktop/src-tauri/tauri.conf.json").read_text(encoding="utf-8")
    )
    android = (root / "apps/android/app/build.gradle.kts").read_text(encoding="utf-8")
    version_match = ANDROID_VERSION.search(android)
    code_match = ANDROID_VERSION_CODE.search(android)
    if version_match is None or code_match is None:
        raise ValueError("Android Gradle metadata must declare versionName and versionCode")
    return {
        "cargo": str(cargo["workspace"]["package"]["version"]),
        "package": str(root_package["version"]),
        "desktop_package": str(desktop_package["version"]),
        "tauri": str(tauri["version"]),
        "android": version_match.group(1),
        "android_version_code": code_match.group(1),
    }


def validate_versions(tag: str, versions: dict[str, str]) -> list[str]:
    match = SEMVER.fullmatch(tag)
    if match is None:
        return ["tag must use vMAJOR.MINOR.PATCH stable SemVer syntax"]
    expected = ".".join(match.groups())
    errors = [
        f"{field} version {value} does not match tag {expected}"
        for field, value in versions.items()
        if field != "android_version_code" and value != expected
    ]
    try:
        expected_code = str(android_version_code(expected))
    except ValueError as error:
        errors.append(str(error))
    else:
        if versions.get("android_version_code") != expected_code:
            errors.append(
                f"Android versionCode {versions.get('android_version_code')} does not match {expected_code} for {expected}"
            )
    return errors


def gh_json(endpoint: str) -> dict[str, Any]:
    result = subprocess.run(
        ["gh", "api", endpoint], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"gh api failed for {endpoint}")
    return json.loads(result.stdout)


def verify_ci_check(repository: str, sha: str) -> dict[str, Any]:
    response = gh_json(f"repos/{repository}/commits/{sha}/check-runs?filter=latest&per_page=100")
    matches = [
        check
        for check in response.get("check_runs", [])
        if check.get("name") == "CI required"
        and check.get("head_sha") == sha
        and check.get("app", {}).get("id") == 15368
    ]
    if len(matches) != 1 or matches[0].get("conclusion") != "success":
        raise RuntimeError(
            f"exact SHA {sha} has no successful latest GitHub Actions check named CI required"
        )
    return {"name": "CI required", "head_sha": sha, "check_run_id": matches[0]["id"]}


def verify_deep_run(repository: str, sha: str) -> dict[str, Any]:
    response = gh_json(
        f"repos/{repository}/actions/workflows/deep-verification.yml/runs?head_sha={sha}&event=workflow_dispatch&per_page=100"
    )
    runs = sorted(
        (
            run
            for run in response.get("workflow_runs", [])
            if run.get("head_sha") == sha and run.get("event") == "workflow_dispatch"
        ),
        key=lambda run: run.get("created_at", ""),
        reverse=True,
    )
    if not runs:
        raise RuntimeError(
            f"no manually dispatched Deep verification run exists for exact SHA {sha}"
        )
    run = runs[0]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise RuntimeError(
            f"latest Deep verification run {run.get('id')} for {sha} is not successful"
        )
    jobs = gh_json(
        f"repos/{repository}/actions/runs/{run['id']}/jobs?per_page=100"
    ).get("jobs", [])
    errors = validate_deep_jobs(jobs)
    if not jobs or errors:
        raise RuntimeError(
            f"Deep verification run {run['id']} is incomplete: {'; '.join(errors)}"
        )
    return {
        "workflow_run_id": run["id"],
        "html_url": run.get("html_url"),
        "head_sha": sha,
        "job_count": len(jobs),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    try:
        versions = release_versions()
        errors = validate_versions(args.tag, versions)
        if errors:
            raise RuntimeError("; ".join(errors))
        repository = os.environ["GITHUB_REPOSITORY"]
        evidence = {
            "tag": args.tag,
            "source_sha": args.sha,
            "versions": versions,
            "ci": verify_ci_check(repository, args.sha),
            "deep_verification": verify_deep_run(repository, args.sha),
        }
    except (KeyError, OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"::error::{error}" if os.environ.get("GITHUB_ACTIONS") else error, file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
