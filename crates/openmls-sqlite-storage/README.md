# OpenMLS SQLite Storage

A codec-independent storage provider implementing the `StorageProvider` trait from `openmls_traits` based on the `rusqlite` crate.

## Lattice local fork

This workspace copy is based on OpenMLS `openmls_sqlite_storage` 0.3.0, licensed under MIT. The upstream source and license notices are retained. The local fork uses `rusqlite` 0.39, whose `wasm32-unknown-unknown` build exposes the `sqlite-wasm-rs` backend also used by the compatible `sqlite-wasm-vfs` 0.2 VFS.

For browser use, the caller must install a persistent VFS before opening the database, keep access in one dedicated worker, and use a single active connection per database. The Lattice OPFS initializer is in `lattice_mls::api::install_browser_opfs_vfs`. Browser/Core profile opening and identity-key protection are not implemented by this storage provider.
