use std::collections::{BTreeMap, BTreeSet};

use lattice_events::VerifiedSignatureOnlyEvent;
use lattice_storage::{MAX_EVENT_PAGE_SIZE, Store};
use lattice_sync::{
    AuthorId, AuthorSummary, EventId, KnownEvent, MAX_AUTHORS, MAX_DEPENDENCY_REQUESTS,
    MAX_KNOWN_EVENTS, ScopeId, ScopeSummary,
};

use super::{
    SyncEventRecord, SyncEventSource, SyncRequestTarget, SyncSourceError, SyncSummarySource,
};

const MAX_SUMMARY_SOURCE_SCAN_EVENTS: usize = 16_384;
const MAX_SUMMARY_SOURCE_SCAN_BYTES: usize = 16 * 1024 * 1024;

/// Reads committed, signature-verified events for one explicitly selected Space generation.
///
/// The caller assigns the opaque sync scope to the supplied Space/group pair. This
/// source never enumerates other Spaces and never includes pending event rows.
pub struct StoreSyncEventSource<'a> {
    store: &'a Store,
    scope: ScopeId,
    space_id: [u8; 16],
    group_reference: [u8; 32],
}

impl<'a> StoreSyncEventSource<'a> {
    /// Creates a source restricted to one caller-selected scope and generation.
    #[must_use]
    pub const fn new(
        store: &'a Store,
        scope: ScopeId,
        space_id: [u8; 16],
        group_reference: [u8; 32],
    ) -> Self {
        Self {
            store,
            scope,
            space_id,
            group_reference,
        }
    }
}

impl SyncEventSource for StoreSyncEventSource<'_> {
    fn load(
        &mut self,
        scope: ScopeId,
        target: SyncRequestTarget,
    ) -> Result<Option<SyncEventRecord>, SyncSourceError> {
        if scope != self.scope {
            return Ok(None);
        }

        let record = match target {
            SyncRequestTarget::EventId(event_id) => self.store.load_event(event_id.as_bytes()),
            SyncRequestTarget::Sequence { author, sequence } => self
                .store
                .load_event_by_author_sequence(author.as_bytes(), sequence),
        }
        .map_err(|error| SyncSourceError::new(error.to_string()))?;
        let Some(record) = record else {
            return Ok(None);
        };

        let event = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)
            .map_err(|error| SyncSourceError::new(error.to_string()))?;
        if event.event_id().as_bytes() != &record.event_id
            || event.author_fingerprint() != &record.author_id
            || event.author_sequence() != record.author_seq
        {
            return Err(SyncSourceError::new(
                "stored event metadata does not match its signed bytes",
            ));
        }
        if event.space_id() != &self.space_id
            || event.mls_group_reference() != &self.group_reference
        {
            return Ok(None);
        }

        Ok(Some(SyncEventRecord {
            author: AuthorId::new(record.author_id),
            sequence: record.author_seq,
            event_id: EventId::new(record.event_id),
            bytes: record.canonical_bytes,
        }))
    }
}

/// Builds one bounded summary from committed and dependency-pending events in a selected Space generation.
///
/// Event rows are signature-verified before their signed scope and metadata are
/// used. Pending rows contribute missing dependency IDs but are not treated as
/// accepted history. The source refuses over-budget stores rather than
/// truncating a summary and claiming completeness.
pub struct StoreSyncSummarySource<'a> {
    store: &'a Store,
    scope: ScopeId,
    space_id: [u8; 16],
    group_reference: [u8; 32],
}

impl<'a> StoreSyncSummarySource<'a> {
    /// Creates a source restricted to one caller-selected scope and generation.
    #[must_use]
    pub const fn new(
        store: &'a Store,
        scope: ScopeId,
        space_id: [u8; 16],
        group_reference: [u8; 32],
    ) -> Self {
        Self {
            store,
            scope,
            space_id,
            group_reference,
        }
    }
}

impl SyncSummarySource for StoreSyncSummarySource<'_> {
    fn load_summary(&mut self, scope: ScopeId) -> Result<ScopeSummary, SyncSourceError> {
        if scope != self.scope {
            return Err(SyncSourceError::new(
                "requested sync scope does not match selected Space generation",
            ));
        }
        let mut budget = SummaryScanBudget::default();
        let authors =
            load_author_summaries(self.store, self.space_id, self.group_reference, &mut budget)?;
        let missing_dependencies = load_pending_dependencies(
            self.store,
            self.space_id,
            self.group_reference,
            &mut budget,
        )?;
        Ok(ScopeSummary {
            scope: self.scope,
            authors,
            missing_dependencies,
        })
    }
}

#[derive(Default)]
struct SummaryScanBudget {
    event_count: usize,
    byte_count: usize,
}

impl SummaryScanBudget {
    fn add_event(&mut self, byte_count: usize) -> Result<(), SyncSourceError> {
        self.event_count = self
            .event_count
            .checked_add(1)
            .filter(|count| *count <= MAX_SUMMARY_SOURCE_SCAN_EVENTS)
            .ok_or_else(|| {
                SyncSourceError::new("sync summary source event scan exceeds its bounded limit")
            })?;
        self.add_bytes(byte_count)
    }

    fn add_bytes(&mut self, byte_count: usize) -> Result<(), SyncSourceError> {
        self.byte_count = self
            .byte_count
            .checked_add(byte_count)
            .filter(|count| *count <= MAX_SUMMARY_SOURCE_SCAN_BYTES)
            .ok_or_else(|| {
                SyncSourceError::new("sync summary source byte scan exceeds its bounded limit")
            })?;
        Ok(())
    }
}

fn load_author_summaries(
    store: &Store,
    space_id: [u8; 16],
    group_reference: [u8; 32],
    budget: &mut SummaryScanBudget,
) -> Result<Vec<AuthorSummary>, SyncSourceError> {
    let mut authors = BTreeMap::<AuthorId, Vec<KnownEvent>>::new();
    let mut scoped_event_count = 0;
    let mut after = None;
    loop {
        let page = store
            .list_event_page(after, MAX_EVENT_PAGE_SIZE)
            .map_err(|error| SyncSourceError::new(error.to_string()))?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        after = page.last().map(|record| record.event_id);
        for record in page {
            budget.add_event(record.canonical_bytes.len())?;
            let event = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)
                .map_err(|error| SyncSourceError::new(error.to_string()))?;
            if event.event_id().as_bytes() != &record.event_id
                || event.author_fingerprint() != &record.author_id
                || event.author_sequence() != record.author_seq
            {
                return Err(SyncSourceError::new(
                    "stored event metadata does not match its signed bytes",
                ));
            }
            if event.space_id() != &space_id || event.mls_group_reference() != &group_reference {
                continue;
            }

            scoped_event_count += 1;
            if scoped_event_count > MAX_KNOWN_EVENTS {
                return Err(SyncSourceError::new(
                    "selected Space generation exceeds the bounded known-event summary",
                ));
            }
            authors
                .entry(AuthorId::new(record.author_id))
                .or_default()
                .push(KnownEvent {
                    sequence: record.author_seq,
                    event_id: EventId::new(record.event_id),
                });
            if authors.len() > MAX_AUTHORS {
                return Err(SyncSourceError::new(
                    "selected Space generation exceeds the bounded author summary",
                ));
            }
        }
        if page_len < MAX_EVENT_PAGE_SIZE {
            break;
        }
    }

    Ok(authors
        .into_iter()
        .map(|(author, mut known_events)| {
            known_events.sort_unstable_by_key(|known| known.sequence);
            let mut contiguous_sequence: u64 = 0;
            for known in &known_events {
                if known.sequence != contiguous_sequence.saturating_add(1) {
                    break;
                }
                contiguous_sequence = known.sequence;
            }
            AuthorSummary {
                author,
                contiguous_sequence,
                known_events,
                unavailable: Vec::new(),
            }
        })
        .collect())
}

fn load_pending_dependencies(
    store: &Store,
    space_id: [u8; 16],
    group_reference: [u8; 32],
    budget: &mut SummaryScanBudget,
) -> Result<Vec<EventId>, SyncSourceError> {
    let mut missing_dependencies = BTreeSet::new();
    for pending in store
        .list_pending()
        .map_err(|error| SyncSourceError::new(error.to_string()))?
    {
        budget.add_bytes(pending.canonical_bytes.len())?;
        let event = VerifiedSignatureOnlyEvent::decode_verify(&pending.canonical_bytes)
            .map_err(|error| SyncSourceError::new(error.to_string()))?;
        if event.event_id().as_bytes() != &pending.event_id {
            return Err(SyncSourceError::new(
                "pending event ID does not match its signed bytes",
            ));
        }
        if event.space_id() == &space_id && event.mls_group_reference() == &group_reference {
            missing_dependencies.extend(pending.missing_dependencies.into_iter().map(EventId::new));
            if missing_dependencies.len() > MAX_DEPENDENCY_REQUESTS {
                return Err(SyncSourceError::new(
                    "selected Space generation exceeds the bounded dependency summary",
                ));
            }
        }
    }
    Ok(missing_dependencies.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
    use lattice_identity::DeviceIdentity;
    use lattice_storage::{CommitOutcome, Store};

    fn database_path() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "lattice-node-sync-source-{}-{nonce}.sqlite",
            std::process::id()
        ))
    }

    #[test]
    fn store_source_loads_only_verified_events_from_the_selected_generation() {
        let path = database_path();
        let identity = DeviceIdentity::generate().expect("generate identity");
        let space_id = [0x11; 16];
        let group_reference = [0x22; 32];
        let event = VerifiedSignatureOnlyEvent::create(
            &identity,
            EventDraft {
                space_id,
                channel_id: Some([0x33; 16]),
                author_sequence: 1,
                lamport: 1,
                wall_time_hint: 0,
                parents: Vec::new(),
                kind: EventKind::Message,
                protected_body: vec![0x80],
                mls_group_reference: group_reference,
                mls_epoch: 0,
            },
        )
        .expect("create signed event");
        let event_id = *event.event_id().as_bytes();
        let bytes = event.encoded_bytes().to_vec();
        let mut store = Store::open(&path).expect("open test store");
        assert_eq!(
            store
                .commit_authored(identity.fingerprint(), event_id, 1, &bytes, &[])
                .expect("commit signed event"),
            CommitOutcome::Inserted
        );
        let corrupt_id = [0x55; 32];
        store
            .commit_authored([0x77; 32], corrupt_id, 1, &bytes, &[])
            .expect("store mismatched metadata fixture");

        let scope = ScopeId::new([0x44; 32]);
        let mut source = StoreSyncEventSource::new(&store, scope, space_id, group_reference);
        let by_id = source
            .load(scope, SyncRequestTarget::EventId(EventId::new(event_id)))
            .expect("resolve event ID")
            .expect("event exists in selected generation");
        assert_eq!(by_id.bytes, bytes);
        assert_eq!(by_id.author, AuthorId::new(identity.fingerprint()));
        assert_eq!(by_id.sequence, 1);
        assert!(
            source
                .load(scope, SyncRequestTarget::EventId(EventId::new(corrupt_id)))
                .is_err()
        );

        assert!(
            source
                .load(
                    ScopeId::new([0x55; 32]),
                    SyncRequestTarget::EventId(EventId::new(event_id))
                )
                .expect("reject unrelated sync scope")
                .is_none()
        );
        assert!(
            source
                .load(
                    scope,
                    SyncRequestTarget::Sequence {
                        author: AuthorId::new([0x66; 32]),
                        sequence: 1,
                    },
                )
                .expect("resolve unrelated author sequence")
                .is_none()
        );
        drop(store);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn store_summary_source_filters_generation_and_reports_sparse_and_pending_ids() {
        let path = database_path();
        let identity = DeviceIdentity::generate().expect("generate identity");
        let pending_identity = DeviceIdentity::generate().expect("generate pending signer");
        let space_id = [0x11; 16];
        let group_reference = [0x22; 32];
        let other_space_id = [0x33; 16];
        let other_group_reference = [0x44; 32];
        let scope = ScopeId::new([0x55; 32]);
        let mut store = Store::open(&path).expect("open test store");

        let first = signed_event(&identity, space_id, group_reference, 1, None);
        commit(&mut store, &identity, &first);
        let other_generation =
            signed_event(&identity, other_space_id, other_group_reference, 2, None);
        commit(&mut store, &identity, &other_generation);
        let third = signed_event(&identity, space_id, group_reference, 3, None);
        commit(&mut store, &identity, &third);

        let missing_parent = signed_event(&pending_identity, space_id, group_reference, 1, None);
        let missing_dependency = *missing_parent.event_id().as_bytes();
        let pending = signed_event(
            &pending_identity,
            space_id,
            group_reference,
            2,
            Some(&missing_parent),
        );
        store
            .store_pending(
                *pending.event_id().as_bytes(),
                pending.encoded_bytes(),
                &[missing_dependency],
            )
            .expect("store unresolved generation event");

        let mut source = StoreSyncSummarySource::new(&store, scope, space_id, group_reference);
        let summary = source.load_summary(scope).expect("load scoped summary");
        assert_eq!(summary.scope, scope);
        assert_eq!(summary.authors.len(), 1);
        assert_eq!(
            summary.authors[0].author,
            AuthorId::new(identity.fingerprint())
        );
        assert_eq!(summary.authors[0].contiguous_sequence, 1);
        assert_eq!(
            summary.authors[0].known_events,
            vec![
                KnownEvent {
                    sequence: 1,
                    event_id: EventId::new(*first.event_id().as_bytes()),
                },
                KnownEvent {
                    sequence: 3,
                    event_id: EventId::new(*third.event_id().as_bytes()),
                },
            ]
        );
        assert_eq!(
            summary.missing_dependencies,
            vec![EventId::new(missing_dependency)]
        );
        assert!(source.load_summary(ScopeId::new([0x66; 32])).is_err());

        drop(store);
        let _ = std::fs::remove_file(path);
    }
    #[tokio::test]
    async fn store_summaries_drive_authenticated_v2_range_repair() {
        let alice_path = database_path();
        let bob_path = database_path();
        let space_id = [0x71; 16];
        let group_reference = [0x72; 32];
        let scope = super::super::space_generation_scope_id(&space_id, &group_reference);
        let alice = DeviceIdentity::generate().expect("generate initiator identity");
        let bob = DeviceIdentity::generate().expect("generate responder identity");
        let event = signed_event(&bob, space_id, group_reference, 1, None);
        let event_id = EventId::new(*event.event_id().as_bytes());
        let event_bytes = event.encoded_bytes().to_vec();
        let alice_store = Store::open(&alice_path).expect("open initiator store");
        let mut bob_store = Store::open(&bob_path).expect("open responder store");
        commit(&mut bob_store, &bob, &event);

        let mut alice_summary_source =
            StoreSyncSummarySource::new(&alice_store, scope, space_id, group_reference);
        let local_summary = alice_summary_source
            .load_summary(scope)
            .expect("load initiator summary");
        let mut bob_summary_source =
            StoreSyncSummarySource::new(&bob_store, scope, space_id, group_reference);
        let mut bob_event_source =
            StoreSyncEventSource::new(&bob_store, scope, space_id, group_reference);

        let alice_pins_bob = lattice_identity::PinnedIdentity::from_verified_fingerprint(
            bob.public_bundle(),
            bob.fingerprint(),
        )
        .expect("pin responder identity");
        let bob_pins_alice = lattice_identity::PinnedIdentity::from_verified_fingerprint(
            alice.public_bundle(),
            alice.fingerprint(),
        )
        .expect("pin initiator identity");
        let listener = lattice_transport::TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind test listener");
        let endpoint = listener.local_addr().expect("read test endpoint");
        let (client_adapter, server_adapter) = tokio::join!(
            lattice_transport::TcpPeerAdapter::connect(endpoint, 4096),
            listener.accept()
        );
        let client_adapter = client_adapter.expect("connect test adapter");
        let (server_adapter, _) = server_adapter.expect("accept test adapter");
        let mut deduplicator =
            lattice_router::EventDeduplicator::new(8).expect("create bounded deduplicator");
        let mut validator = |requested_scope: ScopeId,
                             event_author: AuthorId,
                             sequence: u64,
                             expected_id: Option<EventId>,
                             bytes: &[u8]| {
            let event = VerifiedSignatureOnlyEvent::decode_verify(bytes)
                .map_err(|_| "invalid signed test event")?;
            let actual_id = EventId::new(*event.event_id().as_bytes());
            if requested_scope == scope
                && event_author == AuthorId::new(bob.fingerprint())
                && sequence == 1
                && expected_id == Some(event_id)
                && actual_id == event_id
            {
                Ok(actual_id)
            } else {
                Err("event does not match the scoped summary")
            }
        };
        let client_cancellation = tokio_util::sync::CancellationToken::new();
        let server_cancellation = tokio_util::sync::CancellationToken::new();
        let (client_result, server_result) = tokio::join!(
            super::super::execute_authenticated_sync_v2_once(
                &client_adapter,
                &alice,
                alice_pins_bob,
                &local_summary,
                &mut deduplicator,
                &mut validator,
                |peer, requested_scope| {
                    peer.fingerprint() == bob.fingerprint() && requested_scope == scope
                },
                &client_cancellation,
            ),
            super::super::serve_authenticated_sync_v2_once(
                &server_adapter,
                &bob,
                bob_pins_alice,
                &mut bob_summary_source,
                &mut bob_event_source,
                |peer, requested_scope| {
                    peer.fingerprint() == alice.fingerprint() && requested_scope == scope
                },
                &server_cancellation,
            ),
        );
        let client_result = client_result.expect("complete authenticated sync");
        let server_result = server_result.expect("serve authenticated sync");
        assert_eq!(client_result.exchange.events.len(), 1);
        assert_eq!(client_result.exchange.events[0].event_id, event_id);
        assert_eq!(client_result.exchange.events[0].bytes, event_bytes);
        assert_eq!(server_result.exchange.included_events, 1);

        drop(alice_store);
        drop(bob_store);
        let _ = std::fs::remove_file(alice_path);
        let _ = std::fs::remove_file(bob_path);
    }

    fn signed_event(
        identity: &DeviceIdentity,
        space_id: [u8; 16],
        group_reference: [u8; 32],
        author_sequence: u64,
        parent: Option<&VerifiedSignatureOnlyEvent>,
    ) -> VerifiedSignatureOnlyEvent {
        let parents = parent.map_or_else(Vec::new, |event| vec![event.event_id()]);
        VerifiedSignatureOnlyEvent::create(
            identity,
            EventDraft {
                space_id,
                channel_id: Some([0x66; 16]),
                author_sequence,
                lamport: author_sequence,
                wall_time_hint: 0,
                parents,
                kind: EventKind::Message,
                protected_body: vec![0x80],
                mls_group_reference: group_reference,
                mls_epoch: 0,
            },
        )
        .expect("create signed test event")
    }

    fn commit(store: &mut Store, identity: &DeviceIdentity, event: &VerifiedSignatureOnlyEvent) {
        store
            .commit_authored(
                identity.fingerprint(),
                *event.event_id().as_bytes(),
                event.author_sequence(),
                event.encoded_bytes(),
                &[],
            )
            .expect("commit signed test event");
    }
}
