import unittest
from datetime import date
from cargo_license_policy import validate_packages
from gitleaks_policy import validate_findings
from security_policy import validate_bun_findings


class BunSecurityPolicyTests(unittest.TestCase):
    advisory = "https://github.com/advisories/GHSA-example"

    def exception(self, **updates):
        return {
            "package": "braces",
            "advisory": self.advisory,
            "owner": "@security-owner",
            "reason": "No patched release is available.",
            "expires": "2030-01-01",
            "tracking_issue": 37,
            **updates,
        }

    def test_current_exact_exception_is_allowed_until_expiry(self):
        errors = validate_bun_findings(
            {"braces": [{"url": self.advisory}]},
            [self.exception()],
            today=date(2029, 12, 31),
        )
        self.assertEqual(errors, [])

    def test_unapproved_advisory_fails(self):
        errors = validate_bun_findings(
            {"braces": [{"url": self.advisory}, {"url": "https://example.invalid/new"}]},
            [self.exception()],
            today=date(2029, 12, 31),
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("unapproved Bun advisory", errors[0])

    def test_expired_exception_fails(self):
        errors = validate_bun_findings(
            {"braces": [{"url": self.advisory}]},
            [self.exception(expires="2029-12-31")],
            today=date(2029, 12, 31),
        )
        self.assertTrue(any("expired" in error for error in errors))

    def test_stale_exception_fails(self):
        errors = validate_bun_findings(
            {},
            [self.exception()],
            today=date(2029, 12, 31),
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("stale Bun exception", errors[0])

    def test_exception_requires_tracking_issue_and_expiry(self):
        errors = validate_bun_findings(
            {"braces": [{"url": self.advisory}]},
            [self.exception(tracking_issue=0)],
            today=date(2029, 12, 31),
        )
        self.assertTrue(any("tracking_issue" in error for error in errors))


class CargoLicensePolicyTests(unittest.TestCase):
    allowed = {"MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception"}

    def exception(self, **updates):
        return {
            "package": "fiat-crypto",
            "version": "0.2.9",
            "license": "BSD-1-Clause",
            "owner": "@security-owner",
            "reason": "Maintainer-approved temporary exception.",
            "expires": "2026-11-06",
            "tracking_issue": 37,
            **updates,
        }

    def package(self, **updates):
        return {
            "name": "fiat-crypto",
            "version": "0.2.9",
            "source": "registry+https://example",
            "license": "BSD-1-Clause",
            **updates,
        }

    def test_allows_current_exact_license_exception(self):
        errors = validate_packages(
            [self.package()],
            self.allowed,
            [self.exception()],
            today=date(2026, 11, 5),
        )
        self.assertEqual(errors, [])

    def test_exception_is_scoped_to_package_version_and_license(self):
        errors = validate_packages(
            [self.package(version="0.3.0")],
            self.allowed,
            [self.exception()],
            today=date(2026, 11, 5),
        )
        self.assertTrue(any("unapproved license token" in error for error in errors))
        self.assertTrue(any("stale Cargo license exception" in error for error in errors))

    def test_expired_license_exception_fails_closed(self):
        errors = validate_packages(
            [self.package()],
            self.allowed,
            [self.exception()],
            today=date(2026, 11, 6),
        )
        self.assertTrue(any("exception expired" in error for error in errors))
        self.assertTrue(any("unapproved license token" in error for error in errors))

    def test_unused_license_exception_is_stale(self):
        errors = validate_packages(
            [],
            self.allowed,
            [self.exception()],
            today=date(2026, 11, 5),
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("stale Cargo license exception", errors[0])

    def test_allows_approved_license_expression_on_registry_packages(self):
        packages = [
            {"name": "dep", "version": "1.0.0", "source": "registry+https://example", "license": "MIT OR Apache-2.0"}
        ]
        self.assertEqual(validate_packages(packages, self.allowed), [])

    def test_rejects_unknown_license_and_missing_registry_license(self):
        packages = [
            {"name": "unknown", "version": "1.0.0", "source": "registry+https://example", "license": "LicenseRef-Unknown"},
            {"name": "missing", "version": "1.0.0", "source": "registry+https://example"},
        ]
        errors = validate_packages(packages, self.allowed)
        self.assertEqual(len(errors), 2)

    def test_first_party_license_remains_an_owner_decision(self):
        packages = [{"name": "workspace", "version": "0.1.0", "source": None}]
        self.assertEqual(validate_packages(packages, self.allowed), [])

    def test_with_exception_requires_approved_combination(self):
        package = {
            "name": "exception-license",
            "version": "1.0.0",
            "source": "registry+https://example",
            "license": "Apache-2.0 WITH LLVM-exception",
        }
        self.assertEqual(validate_packages([package], self.allowed), [])
        self.assertTrue(validate_packages([package], {"Apache-2.0"}))

class GitleaksPolicyTests(unittest.TestCase):
    fingerprint = "commit:path:rule:1"

    def exception(self, **updates):
        return {
            "fingerprint": self.fingerprint,
            "owner": "@security-owner",
            "reason": "Reviewed test fixture false positive.",
            "expires": "2030-01-01",
            "tracking_issue": 37,
            **updates,
        }

    def test_exact_current_exception_is_allowed(self):
        findings = [{"Fingerprint": self.fingerprint}]
        self.assertEqual(
            validate_findings(
                findings, [self.exception()], today=date(2029, 12, 31)
            ),
            [],
        )

    def test_unapproved_and_stale_findings_fail(self):
        findings = [{"Fingerprint": "new:finding"}]
        errors = validate_findings(
            findings, [self.exception()], today=date(2029, 12, 31)
        )
        self.assertTrue(any("unapproved Gitleaks finding" in error for error in errors))
        self.assertTrue(any("stale Gitleaks exception" in error for error in errors))

    def test_expired_exception_fails(self):
        findings = [{"Fingerprint": self.fingerprint}]
        errors = validate_findings(
            findings,
            [self.exception(expires="2029-12-31")],
            today=date(2029, 12, 31),
        )
        self.assertTrue(any("future expiry" in error for error in errors))

if __name__ == "__main__":
    unittest.main()
