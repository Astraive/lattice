use lattice_events::VerifiedSignatureOnlyEvent;
use lattice_storage::Store;
use lattice_sync::{AuthorId, EventId, ScopeId};

use super::{SyncEventRecord, SyncEventSource, SyncRequestTarget, SyncSourceError};

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
}
