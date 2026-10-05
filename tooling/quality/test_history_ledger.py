from __future__ import annotations

import csv
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import history_ledger


class HistoryLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Ledger Test")
        self.git("config", "user.email", "ledger-test@example.invalid")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str) -> str:
        result = subprocess.run(
            ("git", *args),
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def commit(self, path: str, content: str, subject: str) -> str:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        self.git("add", path)
        self.git("commit", "-m", subject)
        return self.git("rev-parse", "HEAD")

    def test_history_is_deduplicated_union_of_requested_refs(self) -> None:
        root = self.commit("docs/start.md", "start\n", "docs: initial history")
        self.git("branch", "beta", root)
        main_commit = self.commit("apps/cli/main.rs", "main\n", "feat(cli): main work")
        self.git("checkout", "beta")
        beta_commit = self.commit("apps/android/Main.kt", "beta\n", "feat(android): beta work")
        self.git("checkout", "main")
        head_commit = self.commit("protocol/specs/example.md", "head\n", "docs(protocol): head work")

        commits = history_ledger.collect_commits(
            self.repo, ("refs/heads/main", "refs/heads/beta", "HEAD", "refs/heads/main")
        )

        self.assertEqual({commit.sha for commit in commits}, {root, main_commit, beta_commit, head_commit})
        self.assertEqual(len(commits), 4)
        by_sha = {commit.sha: commit for commit in commits}
        self.assertEqual(by_sha[main_commit].paths, ("apps/cli/main.rs",))
        self.assertEqual(by_sha[beta_commit].paths, ("apps/android/Main.kt",))


    def test_merge_commit_paths_are_compared_to_first_parent(self) -> None:
        root = self.commit("docs/start.md", "start\n", "docs: initial history")
        self.git("branch", "beta", root)
        self.git("checkout", "beta")
        self.commit("apps/beta.txt", "beta\n", "feat: beta change")
        self.git("checkout", "main")
        self.commit("apps/main.txt", "main\n", "feat: main change")
        self.git("merge", "--no-ff", "beta", "-m", "merge beta history")
        merge_sha = self.git("rev-parse", "HEAD")

        commits = history_ledger.collect_commits(self.repo, ("HEAD",))
        merge = next(commit for commit in commits if commit.sha == merge_sha)

        self.assertEqual(merge.subject, "merge beta history")
        self.assertEqual(merge.paths, ("apps/beta.txt",))

    def test_classifier_records_scaffold_debt_and_requirement_links(self) -> None:
        commit = history_ledger.Commit(
            "abc123",
            "build(test): retain placeholder layout",
            ("tests/e2e/.gitkeep", "apps/android/app/src/MainActivity.kt"),
        )

        classified = history_ledger.classify(commit)

        self.assertIn("android-and-mobile", classified.subsystem_tags)
        self.assertIn("tests-and-fuzzing", classified.subsystem_tags)
        self.assertIn("MOB", classified.requirement_ids)
        self.assertIn("LAT-018", classified.requirement_ids)
        self.assertIn("Placeholder inventory and scaffold debt", classified.feature_assignments)

    def test_render_preserves_reviewed_mapping_and_labels_new_heuristics(self) -> None:
        reviewed = self.commit("docs/REQUIREMENTS.md", "requirements\n", "docs: reviewed source")
        pending = self.commit("crates/lattice-files/src/lib.rs", "files\n", "feat(files): add transfer")
        commits = history_ledger.collect_commits(self.repo, ("HEAD",))
        temporary = Path(self.temporary.name)
        history_path = temporary / "history.csv"
        feature_map_path = temporary / "feature_map.csv"
        history_path.write_text(
            "commit,subject,heuristic_subsystem_tags,heuristic_requirement_ids,touched_paths,audit_state,evidence_reference\n"
            f'"{reviewed}","docs: reviewed source","custom-tag","REQ-1","docs/REQUIREMENTS.md","PENDING-AUDIT","evidence.md"\n',
            encoding="utf-8",
        )
        feature_map_path.write_text(
            "ordinal,commit_short_hash,feature_assignments,subject_and_path_rationale,assignment_basis\n"
            f'"1","{reviewed[:7]}","Reviewed capability","Manually checked","reviewed"\n',
            encoding="utf-8",
        )

        with patch.object(history_ledger, "HISTORY_PATH", history_path), patch.object(
            history_ledger, "FEATURE_MAP_PATH", feature_map_path
        ):
            history_csv, feature_csv, stats = history_ledger.render_history(self.repo, commits)

        history_rows = list(csv.DictReader(history_csv.splitlines()))
        feature_rows = list(csv.DictReader(feature_csv.splitlines()))
        by_sha = {row["commit"]: row for row in history_rows}
        by_short_sha = {row["commit_short_hash"]: row for row in feature_rows}
        self.assertEqual(by_sha[reviewed]["heuristic_subsystem_tags"], "custom-tag")
        self.assertEqual(by_sha[reviewed]["evidence_reference"], "evidence.md")
        self.assertEqual(by_short_sha[reviewed[:7]]["feature_assignments"], "Reviewed capability")
        self.assertEqual(by_short_sha[reviewed[:7]]["assignment_basis"], "reviewed")
        self.assertEqual(by_short_sha[pending[:7]]["assignment_basis"], "subject-path heuristic")
        self.assertIn("Files and transfers", by_short_sha[pending[:7]]["feature_assignments"])
        self.assertEqual(stats["commit_count"], 2)
        self.assertEqual(stats["reviewed_commit_count"], 1)
        self.assertEqual(stats["heuristic_commit_count"], 1)


    def test_structural_debt_inventories_placeholders_and_stub_markers(self) -> None:
        self.commit("tests/e2e/.gitkeep", "", "test: retain e2e placeholder")
        self.commit("crates/example/src/lib.rs", "fn pending() { " + "todo" + "!(); }\n", "test: add marker fixture")

        debt = history_ledger.structural_debt(
            self.repo,
            {"source_capability_groups": [{"id": "example", "status": "FAILED"}]},
        )

        self.assertEqual(debt["tracked_gitkeep_paths"], ["tests/e2e/.gitkeep"])
        self.assertEqual(debt["tracked_gitkeep_count"], 1)
        self.assertEqual(
            debt["explicit_stub_marker_scan"]["matches"],
            [{"path": "crates/example/src/lib.rs", "line": 1, "marker": "todo" + "!("}],
        )
        self.assertEqual(debt["unverified_capability_group_ids"], [{"id": "example", "status": "FAILED"}])

if __name__ == "__main__":
    unittest.main()
