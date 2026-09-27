# Persistence and restart matrix

`PASS` requires a real process/application restart and verification of the same valid persisted state. Unit-level reopen assertions are listed only for their narrower local scope.

| State | Client / subsystem | Evidence now | Status | Remaining acceptance |
| --- | --- | --- | --- | --- |
| Identity and pins | CLI/Core | Windows CLI identity persisted across separate commands; Core pin/identity restart tests recorded in quality ledger | VERIFIED for those tests only | Real Desktop, Android, browser process restart matrix. |
| Space membership and MLS | Core/MLS | Local Welcome/bootstrap and conflict persistence tests in quality ledger | VERIFIED for local test cases only | Cross-client restart and real group exchange. |
| Authored events and local text cache | Core | Core integration tests in quality ledger | VERIFIED for exercised local cases | Actual app/process kill/restart and distributed convergence. |
| Application outbox | Storage/Core | Durable local DB implementation/tests audited | UNVERIFIED after process kill | Terminate between commit/send; restart, retry and event-ID dedup. |
| Pending dependencies | Core/sync | Local repair paths source-audited | UNVERIFIED after restart | Restart with missing parent/Commit and prove eventual projection. |
| Courier queue | Storage/node | Queue persistence and one-hop tests recorded | VERIFIED for local queue/one-hop only | Kill/restart multi-hop and post-auth transfer failure preservation. |
| Relay queue | Relay/node | No product relay publish/retrieve callsite in audit | FAILED as integrated path | Add real product path and independent relay acceptance; then restart test. |
| Attachments | Files/Desktop | Staging reopen/resume tests recorded | VERIFIED for local staging tests only | Process-kill network transfer, destination recovery, Android/CLI/Web. |
| Search | Core/Desktop/CLI | Local behavior tests in quality ledger | VERIFIED for tested local semantics | Real app restart plus edit/tombstone and membership isolation across clients. |
| Browser OPFS profile and messages | Web | Two independent profiles reopened after full page reload; identity fingerprints, membership, message histories and exact event IDs remained unchanged. | VERIFIED for full-page reload/reopen only | Browser process-kill/crash, transaction-boundary recovery, outbox retry, quota behavior and same-profile lock contention. |
| Android local profile | Android | Component/lifecycle build tests only; no physical device | BLOCKED-EXTERNAL for physical restart gate | Two- and three-device procedure with exact app revision and logs. |

Do not conflate `queued`, `forwarded`, `delivered`, or `read`. Each restart test must assert durable state and user-visible projection separately.
