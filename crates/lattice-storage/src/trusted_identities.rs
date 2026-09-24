use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{Result, Store, StoreError};

/// Exact opaque public identity bytes and their caller-computed fingerprint.
///
/// Storage does not parse this bundle or establish whether any human comparison
/// occurred; callers are responsible for validating the bytes before persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedIdentityRecord {
    pub fingerprint: [u8; 32],
    pub public_bundle: [u8; 65],
}

impl Store {
    /// Saves an exact identity fingerprint/bundle pair without replacing an
    /// existing pin. Reinserting the same pair succeeds idempotently.
    ///
    /// This method stores opaque fixed-width bytes only; it does not parse or
    /// validate the identity bundle, or assert that a human comparison occurred.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TrustedIdentityConflict`] if the fingerprint is
    /// already mapped to different bundle bytes, or a database error on failure.
    pub fn save_trusted_identity(&mut self, record: TrustedIdentityRecord) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO trusted_identities(fingerprint, public_bundle)
             VALUES (?1, ?2)
             ON CONFLICT(fingerprint) DO NOTHING",
            params![&record.fingerprint[..], &record.public_bundle[..]],
        )?;
        let stored_bundle: Vec<u8> = transaction.query_row(
            "SELECT public_bundle FROM trusted_identities WHERE fingerprint = ?1",
            params![&record.fingerprint[..]],
            |row| row.get(0),
        )?;
        if stored_bundle.as_slice() != &record.public_bundle[..] {
            return Err(StoreError::TrustedIdentityConflict);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Loads the exact bytes pinned for `fingerprint`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or stored bytes violate the schema.
    pub fn load_trusted_identity(
        &self,
        fingerprint: &[u8; 32],
    ) -> Result<Option<TrustedIdentityRecord>> {
        let bytes = self
            .connection
            .query_row(
                "SELECT fingerprint, public_bundle FROM trusted_identities
                 WHERE fingerprint = ?1",
                params![&fingerprint[..]],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        bytes
            .map(|(fingerprint, public_bundle)| {
                Ok(TrustedIdentityRecord {
                    fingerprint: fingerprint.try_into().map_err(|_| {
                        StoreError::CorruptData("invalid trusted identity fingerprint")
                    })?,
                    public_bundle: public_bundle
                        .try_into()
                        .map_err(|_| StoreError::CorruptData("invalid trusted identity bundle"))?,
                })
            })
            .transpose()
    }
}
