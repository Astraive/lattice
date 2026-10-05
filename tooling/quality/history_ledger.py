#!/usr/bin/env python3
"""Generate and validate the repository's full Git-union history inventory."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
HISTORY_PATH = ROOT / "docs/quality/HISTORY_INDEX.csv"
FEATURE_MAP_PATH = ROOT / "docs/quality/COMMIT_FEATURE_MAP.csv"
LEDGER_PATH = ROOT / "docs/verification/FEATURE_LEDGER.json"
BASE_REFS = ("refs/remotes/origin/main", "refs/remotes/origin/beta")
HISTORY_FIELDS = (
    "commit",
    "subject",
    "heuristic_subsystem_tags",
    "heuristic_requirement_ids",
    "touched_paths",
    "audit_state",
    "evidence_reference",
)
FEATURE_MAP_FIELDS = (
    "ordinal",
    "commit_short_hash",
    "feature_assignments",
    "subject_and_path_rationale",
    "assignment_basis",
)


@dataclass(frozen=True)
class Commit:
    sha: str
    subject: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class Classification:
    subsystem_tags: tuple[str, ...]
    requirement_ids: tuple[str, ...]
    feature_assignments: tuple[str, ...]


PATH_RULES = (
    ("apps/android/", "android-and-mobile", ("MOB", "LAT-001", "LAT-008", "LAT-009", "LAT-010", "LAT-013", "LAT-016"), "Android client"),
    ("apps/ios/", "android-and-mobile", ("MOB", "LAT-001", "LAT-008", "LAT-009", "LAT-010", "LAT-013", "LAT-016"), "iOS client"),
    ("apps/desktop/", "desktop", ("DSK", "LAT-002", "LAT-004"), "Desktop client"),
    ("apps/web/", "web-and-browser", ("WEB", "LAT-002", "LAT-004"), "Web client"),
    ("apps/cli/", "cli-and-node", ("CLI", "NET", "LAT-004"), "CLI and node"),
    ("crates/lattice-identity/", "identity-trust-pki", ("IDN", "LAT-009"), "Identity and trust"),
    ("crates/lattice-crypto/", "identity-trust-pki", ("IDN", "LAT-009"), "Cryptography and trust"),
    ("crates/lattice-core/", "spaces-and-mls", ("SPC", "IDN-004", "IDN-008", "LAT-003", "LAT-007"), "Core, Spaces and MLS"),
    ("crates/lattice-mls/", "spaces-and-mls", ("SPC", "IDN-004", "IDN-008", "LAT-003", "LAT-007"), "MLS and Spaces"),
    ("crates/lattice-events/", "protocol-events-vectors", ("LAT-002", "LAT-003", "LAT-006", "LAT-011", "LAT-018"), "Protocol events and vectors"),
    ("crates/lattice-protocol/", "protocol-events-vectors", ("LAT-002", "LAT-003", "LAT-006", "LAT-011", "LAT-018"), "Protocol and encoding"),
    ("protocol/", "protocol-events-vectors", ("LAT-002", "LAT-003", "LAT-006", "LAT-011", "LAT-018"), "Protocol specifications and vectors"),
    ("crates/lattice-storage/", "storage-outbox-courier", ("LAT-004", "LAT-005", "LAT-006"), "Storage and outbox"),
    ("crates/lattice-node/", "cli-and-node", ("CLI", "NET", "LAT-004"), "Node and sync"),
    ("crates/lattice-sync/", "sync-routing-transport", ("NET", "LAT-002", "LAT-005", "LAT-007", "LAT-011"), "Sync and routing"),
    ("crates/lattice-router/", "sync-routing-transport", ("NET", "LAT-002", "LAT-005", "LAT-007", "LAT-011"), "Routing and transport"),
    ("crates/lattice-transport/", "sync-routing-transport", ("NET", "LAT-002", "LAT-005", "LAT-007", "LAT-011"), "Transport"),
    ("crates/lattice-mesh/", "sync-routing-transport", ("NET", "LAT-002", "LAT-005", "LAT-007", "LAT-011"), "Mesh networking"),
    ("crates/lattice-files/", "files-and-transfers", ("FIL", "LAT-006"), "Files and transfers"),
    ("crates/lattice-relay/", "relay", ("NET-009", "NET-010", "NET-011", "NET-013"), "Relay"),
    ("crates/lattice-voice/", "voice", ("VOC", "LAT-016", "LAT-017"), "Voice"),
    ("tests/", "tests-and-fuzzing", ("LAT-006", "LAT-007", "LAT-018"), "Verification and tests"),
    ("fuzz/", "tests-and-fuzzing", ("LAT-006", "LAT-007", "LAT-018"), "Fuzzing and tests"),
    ("docs/", "requirements-and-architecture", (), "Requirements and architecture"),
    (".github/", "build-repository-maintenance", (), "Build and CI"),
    ("tooling/", "build-repository-maintenance", (), "Development tooling"),
)


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", *args),
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.decode("utf-8", errors="surrogateescape")


def structural_debt(root: Path, ledger: dict) -> dict:
    tracked_paths = [path for path in git(root, "ls-files", "-z").split("\0") if path]
    placeholders = sorted(path for path in tracked_paths if path.endswith(".gitkeep"))
    marker_tokens = ("TODO: implement", "todo!(", "unimplemented!(", "#[allow(dead_code)]")
    marker_matches: list[dict[str, str | int]] = []
    for relative_path in tracked_paths:
        if relative_path == "tooling/quality/history_ledger.py":
            continue
        path = root / relative_path
        if path.suffix not in {".rs", ".kt", ".ts", ".tsx", ".swift", ".py", ".ps1"}:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            for token in marker_tokens:
                if token in line:
                    marker_matches.append(
                        {"path": relative_path, "line": line_number, "marker": token}
                    )
    unverified_groups = [
        {"id": group["id"], "status": group["status"]}
        for group in ledger["source_capability_groups"]
        if group["status"] != "VERIFIED"
    ]
    return {
        "tracked_gitkeep_paths": placeholders,
        "tracked_gitkeep_count": len(placeholders),
        "explicit_stub_marker_scan": {
            "scanned_source_extensions": [".rs", ".kt", ".ts", ".tsx", ".swift", ".py", ".ps1"],
            "patterns": list(marker_tokens),
            "matches": marker_matches,
        },
        "unreachable_branch_review": [
            {
                "path": "apps/desktop/src-tauri/src/profile.rs",
                "symbol": "keyring_profile_id",
                "classification": "release-only unreachable branch",
                "reason": "Release configuration cannot select an isolated profile; the panic is guarded by the same debug-only policy.",
            },
            {
                "path": "crates/lattice-protocol/src/lib.rs",
                "symbol": "Reader::read_head",
                "classification": "unreachable parser arm",
                "reason": "The final match arm is outside the 5-bit additional-information domain.",
            },
        ],
        "unverified_capability_group_ids": unverified_groups,
        "review_limit": "Static marker and invariant review is not a complete call-graph dead-code proof; unverified capability groups remain explicit and are not promoted based on code presence.",
    }


def collect_commits(root: Path, refs: Iterable[str]) -> list[Commit]:
    refs = tuple(dict.fromkeys(refs))
    if git(root, "rev-parse", "--is-shallow-repository").strip() == "true":
        raise ValueError("history ledger requires full, non-shallow Git history")
    for ref in refs:
        git(root, "rev-parse", "--verify", "--quiet", ref)
    output = git(
        root,
        "log",
        "--reverse",
        "--topo-order",
        "--format=%H%x09%s%x09%P",
        "--name-only",
        "--no-renames",
        *refs,
    )
    commits: list[Commit] = []
    current_sha = ""
    current_subject = ""
    current_parents: tuple[str, ...] = ()
    current_paths: list[str] = []

    def append_current() -> None:
        if not current_sha:
            return
        paths = set(current_paths)
        if len(current_parents) > 1:
            merge_paths = git(root, "diff", "--name-only", "-z", f"{current_sha}^1", current_sha)
            paths.update(path for path in merge_paths.split("\0") if path)
        commits.append(Commit(current_sha, current_subject, tuple(sorted(paths))))

    for line in output.splitlines():
        if len(line) >= 41 and line[40] == "\t" and all(
            character in "0123456789abcdef" for character in line[:40]
        ):
            append_current()
            full_sha, subject, parent_text = line.split("\t", maxsplit=2)
            current_sha = full_sha
            current_subject = subject
            current_parents = tuple(parent_text.split())
            current_paths = []
        elif line:
            current_paths.append(line)
    append_current()
    expected_shas = set(git(root, "rev-list", *refs).splitlines())
    actual_shas = [commit.sha for commit in commits]
    if len(actual_shas) != len(set(actual_shas)) or set(actual_shas) != expected_shas:
        raise ValueError("Git log inventory does not exactly cover the selected ref union")
    return commits


def classify(commit: Commit) -> Classification:
    tags: set[str] = set()
    requirements: set[str] = set()
    features: set[str] = set()
    for path in commit.paths:
        for prefix, tag, ids, label in PATH_RULES:
            if path.startswith(prefix):
                tags.add(tag)
                requirements.update(ids)
                features.add(label)
    if not tags:
        tags.add("build-repository-maintenance")
        features.add("Repository maintenance")
    if any(path.endswith(".gitkeep") for path in commit.paths):
        features.add("Placeholder inventory and scaffold debt")
    subject = commit.subject.lower()
    if any(token in subject for token in ("security", "credential", "pki", "trust")):
        tags.add("identity-trust-pki")
        requirements.update(("IDN", "LAT-009"))
        features.add("Identity and trust")
    if any(token in subject for token in ("protocol", "vector", "encoding", "wire")):
        tags.add("protocol-events-vectors")
        requirements.update(("LAT-002", "LAT-003", "LAT-006", "LAT-011", "LAT-018"))
        features.add("Protocol and vectors")
    if any(token in subject for token in ("transport", "sync", "routing", "relay", "courier")):
        tags.add("sync-routing-transport")
        requirements.update(("NET", "LAT-002", "LAT-005", "LAT-007", "LAT-011"))
        features.add("Sync, routing and transport")
    return Classification(
        tuple(sorted(tags)),
        tuple(sorted(requirements)),
        tuple(sorted(features)),
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def csv_text(fields: tuple[str, ...], rows: Iterable[dict[str, str]]) -> str:
    from io import StringIO

    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def render_history(root: Path, commits: list[Commit]) -> tuple[str, str, dict[str, int]]:
    old_history = {row["commit"]: row for row in read_csv(HISTORY_PATH)}
    old_map = {row["commit_short_hash"]: row for row in read_csv(FEATURE_MAP_PATH)}
    short_hashes = [commit.sha[:7] for commit in commits]
    if len(short_hashes) != len(set(short_hashes)):
        raise ValueError("commit feature map requires unique seven-character hashes")
    history_rows: list[dict[str, str]] = []
    feature_rows: list[dict[str, str]] = []
    reviewed = 0
    for ordinal, commit in enumerate(commits, start=1):
        prior = old_history.get(commit.sha, {})
        prior_map = old_map.get(commit.sha[:7], {})
        classification = classify(commit)
        history_rows.append(
            {
                "commit": commit.sha,
                "subject": commit.subject,
                "heuristic_subsystem_tags": prior.get("heuristic_subsystem_tags")
                or ";".join(classification.subsystem_tags),
                "heuristic_requirement_ids": prior.get("heuristic_requirement_ids")
                or ";".join(classification.requirement_ids),
                "touched_paths": ";".join(commit.paths),
                "audit_state": prior.get("audit_state") or "PENDING-AUDIT",
                "evidence_reference": prior.get("evidence_reference", ""),
            }
        )
        if prior_map:
            assignment = prior_map.get(
                "feature_assignments", prior_map.get("reviewed_feature_assignments", "")
            )
            rationale = prior_map["subject_and_path_rationale"]
            basis = prior_map.get("assignment_basis", "reviewed")
            reviewed += basis == "reviewed"
        else:
            assignment = "; ".join(classification.feature_assignments)
            rationale = "Subject/path heuristic; capability status and runtime evidence are in FEATURE_LEDGER.json."
            basis = "subject-path heuristic"
        feature_rows.append(
            {
                "ordinal": str(ordinal),
                "commit_short_hash": commit.sha[:7],
                "feature_assignments": assignment,
                "subject_and_path_rationale": rationale,
                "assignment_basis": basis,
            }
        )
    stats = {
        "commit_count": len(commits),
        "reviewed_commit_count": reviewed,
        "heuristic_commit_count": len(commits) - reviewed,
    }
    return (
        csv_text(HISTORY_FIELDS, history_rows),
        csv_text(FEATURE_MAP_FIELDS, feature_rows),
        stats,
    )


def format_json(value: Any, indent: int = 0, *, allow_inline_arrays: bool = True) -> str:
    if isinstance(value, dict):
        if not value:
            return "{}"
        entries = []
        for key, item in value.items():
            prefix = " " * (indent + 2) + json.dumps(key, ensure_ascii=False) + ": "
            if isinstance(item, list) and all(not isinstance(part, (dict, list)) for part in item):
                inline = json.dumps(item, ensure_ascii=False, separators=(", ", ": "))
                if len(prefix) + len(inline) <= 96:
                    entries.append(prefix + inline)
                    continue
            entries.append(
                prefix
                + format_json(
                    item,
                    indent + 2,
                    allow_inline_arrays=not isinstance(item, list),
                )
            )
        return "{\n" + ",\n".join(entries) + "\n" + " " * indent + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        inline = json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
        if (
            allow_inline_arrays
            and all(not isinstance(item, (dict, list)) for item in value)
            and indent + len(inline) <= 96
        ):
            return inline
        entries = [
            " " * (indent + 2) + format_json(item, indent + 2)
            for item in value
        ]
        return "[\n" + ",\n".join(entries) + "\n" + " " * indent + "]"
    return json.dumps(value, ensure_ascii=False)


def render_ledger(root: Path, stats: dict[str, int]) -> str:
    with LEDGER_PATH.open(encoding="utf-8") as source:
        data = json.load(source)
    data["schema_version"] = 2
    data["history_inventory"] = {
        "source_refs": [*BASE_REFS, "checkout base"],
        "snapshot_base_policy": "Indexes the selected refs and prior checkout commit so the snapshot-writing commit is not self-referential; merge commits remain included when reachable.",
        "merge_commits_included": True,
        "indexed_commit_count": stats["commit_count"],
        "feature_mapped_commit_count": stats["commit_count"],
        "reviewed_commit_count": stats["reviewed_commit_count"],
        "heuristic_assignment_count": stats["heuristic_commit_count"],
        "history_index": "docs/quality/HISTORY_INDEX.csv",
        "commit_feature_map": "docs/quality/COMMIT_FEATURE_MAP.csv",
        "scope_complete": True,
        "capability_classification_complete": True,
    }
    data["structural_debt"] = structural_debt(root, data)
    return format_json(data) + "\n"


def update_or_check(path: Path, expected: str, check: bool) -> bool:
    actual = path.read_text(encoding="utf-8") if path.exists() else ""
    if actual == expected:
        return True
    if check:
        print(f"{path.relative_to(ROOT)} is stale; run python tooling/quality/history_ledger.py --write", file=sys.stderr)
        return False
    path.write_text(expected, encoding="utf-8", newline="\n")
    print(f"updated {path.relative_to(ROOT)}")
    return True


def build(root: Path, refs: Iterable[str]) -> tuple[str, str, str, dict[str, int]]:
    commits = collect_commits(root, refs)
    history, feature_map, stats = render_history(root, commits)
    return history, feature_map, render_ledger(root, stats), stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail if committed inventory files are stale")
    mode.add_argument("--write", action="store_true", help="regenerate inventory files")
    parser.add_argument("--head", help="checkout base commit/ref to union with main and beta")
    parser.add_argument("--ref", action="append", dest="base_refs", help="base ref override; repeatable")
    args = parser.parse_args(argv)
    head = args.head or ("HEAD" if args.write else "HEAD^")
    refs = (*tuple(args.base_refs or BASE_REFS), head)
    try:
        history, feature_map, ledger, stats = build(ROOT, refs)
        check = args.check or not args.write
        paths = (
            (HISTORY_PATH, history),
            (FEATURE_MAP_PATH, feature_map),
            (LEDGER_PATH, ledger),
        )
        ok = all(update_or_check(path, content, check) for path, content in paths)
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as error:
        print(f"history ledger: {error}", file=sys.stderr)
        return 2
    if ok:
        print(
            f"history ledger: {stats['commit_count']} commits; "
            f"{stats['reviewed_commit_count']} reviewed feature maps; "
            f"{stats['heuristic_commit_count']} subject/path heuristic maps"
        )
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
