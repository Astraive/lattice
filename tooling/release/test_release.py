import unittest

from sanitize_sbom import remove_personal_metadata
from verify_release import (
    EXPECTED_DEEP_JOBS,
    android_version_code,
    validate_deep_jobs,
    validate_versions,
)


class ReleaseVersionTests(unittest.TestCase):
    def test_android_version_code_is_monotonic_for_semver_components(self):
        self.assertEqual(android_version_code("0.1.0"), 1000)
        self.assertGreater(android_version_code("1.0.0"), android_version_code("0.999.999"))
        self.assertGreater(android_version_code("1.1.0"), android_version_code("1.0.999"))

    def test_android_version_code_rejects_non_semver_and_overflow(self):
        for version in ("0.0.0", "1.0", "01.0.0", "0.1000.0", "2100.0.1"):
            with self.assertRaises(ValueError):
                android_version_code(version)

    def test_all_client_metadata_must_match_release_tag(self):
        versions = {
            "cargo": "0.1.0",
            "package": "0.1.0",
            "desktop_package": "0.1.0",
            "tauri": "0.1.0",
            "android": "0.1.0",
            "android_version_code": "1000",
        }
        self.assertEqual(validate_versions("v0.1.0", versions), [])
        versions["tauri"] = "0.2.0"
        self.assertTrue(validate_versions("v0.1.0", versions))

    def test_only_stable_semver_tags_are_accepted(self):
        self.assertTrue(validate_versions("0.1.0", {}))
        self.assertTrue(validate_versions("v0.1.0-rc.1", {}))


class DeepVerificationGateTests(unittest.TestCase):
    def test_requires_all_expected_jobs_to_succeed(self):
        jobs = [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in EXPECTED_DEEP_JOBS
        ]
        self.assertEqual(validate_deep_jobs(jobs), [])
        self.assertTrue(validate_deep_jobs(jobs[:-1]))

    def test_rejects_cancelled_or_skipped_deep_job(self):
        jobs = [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in EXPECTED_DEEP_JOBS
        ]
        jobs[0]["conclusion"] = "cancelled"
        self.assertTrue(validate_deep_jobs(jobs))


class SbomRedactionTests(unittest.TestCase):
    def test_removes_personal_contact_fields_recursively(self):
        document = {
            "metadata": {"authors": [{"name": "Private", "email": "user@example.invalid"}]},
            "components": [{"name": "library", "author": "Private", "version": "1.0.0"}],
        }
        remove_personal_metadata(document)
        self.assertEqual(
            document,
            {"metadata": {}, "components": [{"name": "library", "version": "1.0.0"}]},
        )


if __name__ == "__main__":
    unittest.main()
