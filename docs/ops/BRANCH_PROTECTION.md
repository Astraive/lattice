# Main branch protection

The active GitHub ruleset `Main` (ID `24044281`) targets `refs/heads/main`. Its required status context is `CI required`, provided by GitHub Actions integration `15368`; strict required-status-check policy is enabled. The ruleset also requires pull requests and prevents deletion and non-fast-forward updates. No bypass actors are configured.

A merge must use the head revision that passed `CI required`. A failed, cancelled, missing, or unexpectedly skipped required check does not authorize merging. If the CI workflow renames its aggregate check, update and verify this ruleset in the same change before relying on the new name.

## Emergency procedure

There is no routine red-CI bypass. For an urgent security or availability incident when the required check is unavailable and waiting is materially unsafe:

1. Open an incident issue and a pull request. Record the incident impact, exact proposed head SHA, CI status or outage evidence, why normal checks cannot be awaited, and the responsible repository administrator.
2. Keep the pull-request requirement and all unrelated rules enabled. A repository administrator may temporarily relax only the `CI required` rule for this incident; do not add a standing bypass actor or permit a direct push.
3. Merge only the reviewed incident fix. Record the merged SHA, the rule change, the administrator, and timestamps in the incident issue. Treat the change as an exception, not successful CI evidence.
4. Restore the required check immediately. Verify through the GitHub API that `Main` is active, strict, targets only `main`, requires the exact `CI required` context, and has no bypass actors. Confirm a subsequent normal PR is gated by that check.
5. Link the audit-log evidence and restoration verification from the incident issue; notify maintainers that normal CI gating is restored.

Any tag-driven release must independently reject a tag unless its source commit is reachable from protected `main` and has successful exact-SHA CI and Deep verification evidence. This does not replace the main-branch ruleset.
