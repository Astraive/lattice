#!/usr/bin/env python3
"""Enforce the explicit test-suite inventory and reject empty required suites."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "tooling/quality/test-suite-policy.json"
TEST_COUNT = re.compile(r"^\s*(\d+)\s+tests?,\s+\d+\s+benchmarks?\s*$", re.MULTILINE)


def fail(message: str) -> None:
    raise SystemExit(f"test suite policy: {message}")


def run(
    command: list[str], cwd: Path, *, emit: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if emit or result.returncode:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    if result.returncode:
        fail(f"command failed ({result.returncode}): {' '.join(command)}")
    return result


SKIP_DIRS = {
    ".git",
    ".gradle",
    ".kotlin",
    ".turbo",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
}


def walk_files(directory: Path):
    for current, directories, filenames in os.walk(directory):
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRS)
        for filename in sorted(filenames):
            yield Path(current) / filename



def check_inventory(policy: dict) -> list[tuple[str, Path]]:
    manifests = sorted(
        path
        for source in (ROOT / "apps", ROOT / "packages")
        for path in walk_files(source)
        if path.name == "package.json"
    )
    declared: dict[str, tuple[Path, str]] = {}
    for path in manifests:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        name = manifest.get("name")
        if not isinstance(name, str):
            fail(f"package manifest has no name: {path.relative_to(ROOT)}")
        scripts = manifest.get("scripts", {})
        test_script = scripts.get("test") if isinstance(scripts, dict) else None
        if test_script is not None:
            declared[name] = (path.parent, test_script)

    required = set(policy["bun"]["required"])
    intentional = set(policy["bun"]["intentional_no_tests"])
    actual = {
        json.loads(path.read_text(encoding="utf-8"))["name"]
        for path in manifests
    }
    if required & intentional or required | intentional != actual:
        fail(
            "Bun inventory differs from package manifests; update required and "
            "intentional_no_tests: "
            f"required={sorted(required)}, intentional_no_tests={sorted(intentional)}, "
            f"manifests={sorted(actual)}"
        )
    if set(declared) != required:
        fail(
            "declared Bun test scripts differ from required inventory: "
            f"declared={sorted(declared)}, required={sorted(required)}"
        )

    suites: list[tuple[str, Path]] = []
    for name in sorted(required):
        package_dir, script = declared[name]
        if "--pass-with-no-tests" in script:
            fail(f"{name} masks an empty suite with --pass-with-no-tests")
        suites.append((name, package_dir))
    return suites


def check_rust_inventory(policy: dict) -> list[str]:
    metadata = json.loads(
        run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            ROOT,
            emit=False,
        ).stdout
    )
    actual = {package["name"] for package in metadata["packages"]}
    required = set(policy["rust"]["required"])
    intentional = set(policy["rust"]["intentional_no_tests"])
    if required & intentional or required | intentional != actual:
        fail(
            "Rust inventory differs from Cargo workspace metadata; update required and "
            "intentional_no_tests: "
            f"overlap={sorted(required & intentional)}, "
            f"missing={sorted((required | intentional) - actual)}, "
            f"unclassified={sorted(actual - required - intentional)}"
        )
    return sorted(required)

def check_gradle_inventory(policy: dict) -> None:
    settings = (ROOT / "apps/android/settings.gradle.kts").read_text(encoding="utf-8")
    projects = set(re.findall(r'"(:[^"]+)"', settings))
    required = set(policy["gradle"]["required"])
    intentional = set(policy["gradle"]["intentional_no_tests"])
    declared = required | intentional
    modules = {task.rsplit(":", 1)[0] for task in declared}
    if required & intentional or modules != projects:
        fail(
            "Gradle inventory differs from settings.gradle.kts; update required and "
            f"intentional_no_tests: overlap={sorted(required & intentional)}, "
            f"missing={sorted(projects - modules)}, unclassified={sorted(modules - projects)}"
        )
    if any(not task.endswith(":testDebugUnitTest") for task in declared):
        fail(f"Gradle test inventory contains unsupported tasks: {sorted(declared)}")




def check_bun_suite(name: str, package_dir: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="lattice-bun-tests-") as tmp:
        report = Path(tmp) / "junit.xml"
        run(
            [
                "bun",
                "run",
                "test",
                "--reporter=junit",
                f"--reporter-outfile={report}",
            ],
            package_dir,
        )
        try:
            root = ET.parse(report).getroot()
            count = int(root.attrib.get("tests", "0"))
        except (ET.ParseError, OSError, ValueError) as error:
            fail(f"{name} did not produce a valid Bun JUnit report: {error}")
        if count <= 0:
            fail(f"{name} discovered zero tests")
        print(f"Bun suite {name}: {count} tests")


def check_rust_suite(name: str) -> None:
    result = run(
        ["cargo", "test", "--locked", "--package", name, "--", "--list"],
        ROOT,
        emit=False,
    )
    counts = [int(match) for match in TEST_COUNT.findall(result.stdout + result.stderr)]
    total = sum(counts)
    if total <= 0:
        fail(f"Rust suite {name} discovered zero tests")
    print(f"Rust suite {name}: {total} tests across {len(counts)} targets")


def check_quarantine_and_workflow_bypasses() -> None:
    workflow_patterns = {
        "continue-on-error": re.compile(r"(?m)^\s*continue-on-error\s*:\s*true\s*$"),
        "pass-with-no-tests": re.compile(r"--pass-with-no-tests"),
        "unconditional success fallback": re.compile(r"\|\|\s*true\b"),
    }
    workflows = {
        * (ROOT / ".github/workflows").glob("*.yml"),
        * (ROOT / ".github/workflows").glob("*.yaml"),
    }
    for path in sorted(workflows):
        text = path.read_text(encoding="utf-8")
        for label, pattern in workflow_patterns.items():
            if pattern.search(text):
                fail(f"workflow bypass {label!r} found in {path.relative_to(ROOT)}")

    marker_patterns = {
        "Rust ignored test": re.compile(r"#\s*\[\s*ignore\b"),
        "Bun/Jest skipped or focused test": re.compile(
            r"\b(?:test|it|describe)\s*\.\s*(?:skip|only)\s*\("
        ),
        "JUnit ignored or disabled test": re.compile(r"@(?:Ignore|Disabled)\b"),
    }
    source_roots = [ROOT / "apps", ROOT / "crates", ROOT / "packages", ROOT / "tests"]
    for source_root in source_roots:
        for path in walk_files(source_root):
            if path.suffix not in {
                ".rs",
                ".ts",
                ".tsx",
                ".js",
                ".jsx",
                ".kt",
            }:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for label, pattern in marker_patterns.items():
                if pattern.search(text):
                    fail(f"{label} marker found in {path.relative_to(ROOT)}")


def main() -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    bun_suites = check_inventory(policy)
    rust_suites = check_rust_inventory(policy)
    check_gradle_inventory(policy)
    check_quarantine_and_workflow_bypasses()
    for name, package_dir in bun_suites:
        check_bun_suite(name, package_dir)
    for name in rust_suites:
        check_rust_suite(name)
    print(
        f"Test suite policy passed: {len(bun_suites)} Bun suites, "
        f"{len(rust_suites)} Rust suites"
    )


if __name__ == "__main__":
    main()
