use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use rusqlite::Connection;
use serde::Serialize;

#[derive(Default)]
struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

#[test]
fn clean_install_runs_every_migration_and_is_idempotent() {
    let mut connection = Connection::open_in_memory().expect("create a fresh SQLite database");
    {
        let mut storage = SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut connection);
        storage
            .run_migrations()
            .expect("apply clean-install migrations");
    }

    let applied: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM openmls_sqlite_storage_migrations",
            [],
            |row| row.get(0),
        )
        .expect("read applied migration history");
    assert_eq!(applied, 6, "all six checked-in migrations must apply");

    let table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'registered_vc_emulation_epochs')",
            [],
            |row| row.get(0),
        )
        .expect("check the latest migration's table");
    assert!(
        table_exists,
        "the latest migration's schema must be present"
    );

    {
        let mut storage = SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut connection);
        storage
            .run_migrations()
            .expect("re-running migrations on an initialized database is safe");
    }

    let applied_after_rerun: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM openmls_sqlite_storage_migrations",
            [],
            |row| row.get(0),
        )
        .expect("read migration history after rerun");
    assert_eq!(
        applied_after_rerun, 6,
        "rerun must not duplicate migrations"
    );
}
