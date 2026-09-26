use std::{
    fs,
    io::Read,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use lattice_core::Client;
use lattice_node::courier::receive_courier_once;
use lattice_platform::{MAX_ENVELOPE_BYTES, OsKeyringProtector};
use lattice_storage::{DEFAULT_COURIER_LIMITS, Store};
use lattice_transport::TcpPeerListener;
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::{Mutex as AsyncMutex, oneshot};
use tokio_util::sync::CancellationToken;

use crate::{encoding, profile};

const CONFIG_FILE: &str = "persistent-peer-mode.json";
const MAX_CONFIG_BYTES: u64 = 512;
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct PeerModeConfig {
    enabled: bool,
    listen_address: SocketAddr,
    peer_fingerprint: [u8; 32],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PersistedPeerModeConfig {
    enabled: bool,
    listen_address: String,
    peer_fingerprint: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PersistentPeerModeStatus {
    enabled: bool,
    running: bool,
    listen_address: Option<String>,
    peer_fingerprint: Option<String>,
    bound_address: Option<String>,
    queued_items: usize,
    queued_bytes: usize,
    max_queued_items: usize,
    max_queued_bytes: usize,
    error: Option<String>,
}

#[derive(Clone)]
pub(crate) struct PeerModeState {
    shared: Arc<PeerModeShared>,
}

struct PeerModeShared {
    lifecycle: AsyncMutex<()>,
    runtime: Mutex<RuntimeState>,
}

struct RuntimeState {
    config: Option<PeerModeConfig>,
    worker: Option<ActiveWorker>,
    running: bool,
    bound_address: Option<String>,
    error: Option<String>,
}

struct ActiveWorker {
    cancellation: CancellationToken,
    finished: oneshot::Receiver<()>,
}

impl PeerModeState {
    pub(crate) fn load() -> Self {
        let (config, error) = match load_config() {
            Ok(config) => (config, None),
            Err(error) => (None, Some(error)),
        };
        Self {
            shared: Arc::new(PeerModeShared {
                lifecycle: AsyncMutex::new(()),
                runtime: Mutex::new(RuntimeState {
                    config,
                    worker: None,
                    running: false,
                    bound_address: None,
                    error,
                }),
            }),
        }
    }

    pub(crate) fn should_autostart(&self) -> bool {
        self.shared
            .runtime
            .lock()
            .is_ok_and(|runtime| runtime.config.as_ref().is_some_and(|config| config.enabled))
    }

    pub(crate) async fn autostart(&self) {
        let _lifecycle = self.shared.lifecycle.lock().await;
        let config = {
            let Ok(runtime) = self.shared.runtime.lock() else {
                return;
            };
            if runtime.worker.is_some() {
                return;
            }
            runtime.config.clone()
        };
        if let Some(config) = config.filter(|config| config.enabled)
            && let Err(error) = self.start_worker(config).await
            && let Ok(mut runtime) = self.shared.runtime.lock()
        {
            runtime.error = Some(error);
        }
    }

    pub(crate) fn cancel_on_exit(&self) {
        if let Ok(runtime) = self.shared.runtime.lock()
            && let Some(worker) = &runtime.worker
        {
            worker.cancellation.cancel();
        }
    }

    fn set_config(&self, config: PeerModeConfig) -> Result<(), String> {
        let mut runtime = self
            .shared
            .runtime
            .lock()
            .map_err(|_| "persistent peer mode state is unavailable".to_owned())?;
        runtime.config = Some(config);
        runtime.error = None;
        Ok(())
    }

    async fn stop_worker(&self) -> Result<(), String> {
        let worker = {
            let mut runtime = self
                .shared
                .runtime
                .lock()
                .map_err(|_| "persistent peer mode state is unavailable".to_owned())?;
            runtime.worker.take()
        };
        if let Some(worker) = worker {
            worker.cancellation.cancel();
            let _ = worker.finished.await;
        }
        let mut runtime = self
            .shared
            .runtime
            .lock()
            .map_err(|_| "persistent peer mode state is unavailable".to_owned())?;
        runtime.running = false;
        runtime.bound_address = None;
        Ok(())
    }

    async fn start_worker(&self, config: PeerModeConfig) -> Result<(), String> {
        let (startup_tx, startup_rx) = oneshot::channel();
        let (finished_tx, finished_rx) = oneshot::channel();
        let cancellation = CancellationToken::new();
        {
            let mut runtime = self
                .shared
                .runtime
                .lock()
                .map_err(|_| "persistent peer mode state is unavailable".to_owned())?;
            runtime.running = false;
            runtime.bound_address = None;
            runtime.error = None;
            runtime.worker = Some(ActiveWorker {
                cancellation: cancellation.clone(),
                finished: finished_rx,
            });
        }

        let shared = Arc::clone(&self.shared);
        tauri::async_runtime::spawn_blocking(move || {
            let mut startup = Some(startup_tx);
            let result = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => match profile::open_profile() {
                    Ok((database_path, protector)) => runtime.block_on(run_listener(
                        config,
                        database_path,
                        protector,
                        cancellation,
                        Arc::clone(&shared),
                        &mut startup,
                    )),
                    Err(error) => Err(error),
                },
                Err(error) => Err(format!("build persistent peer runtime: {error}")),
            };
            if let Err(error) = &result {
                if let Ok(mut runtime) = shared.runtime.lock() {
                    runtime.running = false;
                    runtime.bound_address = None;
                    runtime.error = Some(error.clone());
                }
                if let Some(startup) = startup.take() {
                    let _ = startup.send(Err(error.clone()));
                }
            } else if let Ok(mut runtime) = shared.runtime.lock() {
                runtime.running = false;
                runtime.bound_address = None;
            }
            drop(finished_tx);
        });

        match startup_rx.await {
            Ok(Ok(_bound_address)) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(_) => {
                let error = "persistent peer listener stopped before it was ready".to_owned();
                if let Ok(mut runtime) = self.shared.runtime.lock() {
                    runtime.running = false;
                    runtime.bound_address = None;
                    runtime.error = Some(error.clone());
                }
                Err(error)
            }
        }
    }

    fn status(&self) -> Result<PersistentPeerModeStatus, String> {
        let (config, running, mut bound_address, error) = {
            let runtime = self
                .shared
                .runtime
                .lock()
                .map_err(|_| "persistent peer mode state is unavailable".to_owned())?;
            (
                runtime.config.clone(),
                runtime.running,
                runtime.bound_address.clone(),
                runtime.error.clone(),
            )
        };
        if !running {
            bound_address = None;
        }
        let (database_path, _) = profile::open_profile()?;
        let store = Store::open(database_path).map_err(|error| error.to_string())?;
        let queue = store
            .courier_queue_status()
            .map_err(|error| error.to_string())?;
        let limits = DEFAULT_COURIER_LIMITS;
        Ok(PersistentPeerModeStatus {
            enabled: config.as_ref().is_some_and(|config| config.enabled),
            running,
            listen_address: config
                .as_ref()
                .map(|config| config.listen_address.to_string()),
            peer_fingerprint: config
                .as_ref()
                .map(|config| encoding::hex(&config.peer_fingerprint)),
            bound_address,
            queued_items: queue.usage.items,
            queued_bytes: queue.usage.bytes,
            max_queued_items: limits.max_total_items,
            max_queued_bytes: limits.max_total_bytes,
            error,
        })
    }
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn get_persistent_peer_mode_status(
    state: State<'_, PeerModeState>,
) -> Result<PersistentPeerModeStatus, String> {
    state.status()
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) async fn configure_persistent_peer_mode(
    state: State<'_, PeerModeState>,
    enabled: bool,
    listen_address: String,
    peer_fingerprint: String,
) -> Result<PersistentPeerModeStatus, String> {
    let (requested_config, validation_error) =
        match validate_config(enabled, &listen_address, &peer_fingerprint) {
            Ok(config) => (Some(config), None),
            Err(error) => (None, Some(error)),
        };
    let _lifecycle = state.shared.lifecycle.lock().await;

    if enabled {
        let config = requested_config.ok_or_else(|| {
            validation_error.unwrap_or_else(|| "persistent peer mode config is invalid".to_owned())
        })?;
        state.stop_worker().await?;
        persist_config(&config)?;
        state.set_config(config.clone())?;
        if let Err(error) = state.start_worker(config).await
            && let Ok(mut runtime) = state.shared.runtime.lock()
        {
            runtime.error = Some(error);
        }
    } else {
        let config = requested_config.or_else(|| {
            state
                .shared
                .runtime
                .lock()
                .ok()
                .and_then(|runtime| runtime.config.clone())
                .map(|mut config| {
                    config.enabled = false;
                    config
                })
        });
        state.stop_worker().await?;

        let save_result = match config.as_ref() {
            Some(config) => persist_config(config),
            None => Err(validation_error
                .unwrap_or_else(|| "persistent peer mode config is invalid".to_owned())),
        };
        let state_result = if save_result.is_ok() {
            match config {
                Some(config) => state.set_config(config),
                None => Ok(()),
            }
        } else {
            Ok(())
        };
        let queue_result = (|| {
            let (database_path, _) = profile::open_profile()?;
            let mut store = Store::open(database_path).map_err(|error| error.to_string())?;
            store
                .configure_courier_queue(false, DEFAULT_COURIER_LIMITS)
                .map_err(|error| error.to_string())
        })();
        let mut errors = Vec::new();
        if let Err(error) = save_result {
            errors.push(error);
        }
        if let Err(error) = state_result {
            errors.push(error);
        }
        if let Err(error) = queue_result {
            errors.push(error);
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
    }

    state.status()
}

fn validate_config(
    enabled: bool,
    listen_address: &str,
    peer_fingerprint: &str,
) -> Result<PeerModeConfig, String> {
    let listen_address = listen_address
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid persistent peer listen address: {error}"))?;
    let peer_fingerprint = encoding::parse_fixed_hex::<32>(peer_fingerprint, "peer fingerprint")?;
    Ok(PeerModeConfig {
        enabled,
        listen_address,
        peer_fingerprint,
    })
}

fn config_path() -> Result<PathBuf, String> {
    Ok(profile::data_dir()?.join(CONFIG_FILE))
}

fn load_config() -> Result<Option<PeerModeConfig>, String> {
    let path = config_path()?;
    let mut file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("open persistent peer mode config: {error}")),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect persistent peer mode config: {error}"))?;
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err("persistent peer mode config exceeds its size limit".to_owned());
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| "persistent peer mode config is too large for this platform".to_owned())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read persistent peer mode config: {error}"))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("persistent peer mode config exceeds its size limit".to_owned());
    }
    let persisted: PersistedPeerModeConfig = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse persistent peer mode config: {error}"))?;
    validate_config(
        persisted.enabled,
        &persisted.listen_address,
        &persisted.peer_fingerprint,
    )
    .map(Some)
}

fn persist_config(config: &PeerModeConfig) -> Result<(), String> {
    let path = config_path()?;
    let persisted = PersistedPeerModeConfig {
        enabled: config.enabled,
        listen_address: config.listen_address.to_string(),
        peer_fingerprint: encoding::hex(&config.peer_fingerprint),
    };
    let bytes = serde_json::to_vec(&persisted)
        .map_err(|error| format!("encode persistent peer mode config: {error}"))?;
    fs::write(path, bytes).map_err(|error| format!("save persistent peer mode config: {error}"))
}

async fn run_listener(
    config: PeerModeConfig,
    database_path: PathBuf,
    protector: OsKeyringProtector,
    cancellation: CancellationToken,
    shared: Arc<PeerModeShared>,
    startup: &mut Option<oneshot::Sender<Result<String, String>>>,
) -> Result<(), String> {
    let client = Client::open_existing(&database_path, &protector)
        .map_err(|error| format!("open profile for persistent peer mode: {error}"))?;
    if client
        .pinned_identity(&config.peer_fingerprint)
        .map_err(|error| format!("validate configured peer pin: {error}"))?
        .is_none()
    {
        return Err("configured peer fingerprint is not pinned in this profile".to_owned());
    }

    let listener = TcpPeerListener::bind(config.listen_address, MAX_ENVELOPE_BYTES)
        .await
        .map_err(|error| format!("bind persistent peer listener: {error:?}"))?;
    let bound_address = listener
        .local_addr()
        .map_err(|error| format!("read persistent peer listener address: {error:?}"))?
        .to_string();
    let mut store =
        Store::open(&database_path).map_err(|error| format!("open courier queue: {error}"))?;
    store
        .configure_courier_queue(true, DEFAULT_COURIER_LIMITS)
        .map_err(|error| format!("enable bounded courier queue: {error}"))?;
    if let Ok(mut runtime) = shared.runtime.lock() {
        runtime.running = true;
        runtime.bound_address = Some(bound_address.clone());
        runtime.error = None;
    }
    if let Some(startup) = startup.take() {
        let _ = startup.send(Ok(bound_address));
    }

    loop {
        let (adapter, _) = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted
                .map_err(|error| format!("accept persistent peer connection: {error:?}"))?,
        };
        let session_cancellation = cancellation.clone();
        let adapter_ref = &adapter;
        let store_ref = &mut store;
        let session = client.with_pinned_identity(
            &config.peer_fingerprint,
            |identity, pinned_peer| async move {
                receive_courier_once(
                    adapter_ref,
                    identity,
                    pinned_peer,
                    store_ref,
                    &session_cancellation,
                )
                .await
            },
        );
        let result = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            result = tokio::time::timeout(SESSION_TIMEOUT, session) => result,
        };
        match result {
            Err(_) | Ok(Ok(Some(Ok(_) | Err(_)))) => {}
            Ok(Err(error)) => {
                return Err(format!("validate configured peer pin: {error}"));
            }
            Ok(Ok(None)) => {
                return Err("configured peer fingerprint is no longer pinned".to_owned());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_config;

    #[test]
    fn persistent_peer_config_requires_socket_and_full_fingerprint() {
        let fingerprint = "ab".repeat(32);
        let config = validate_config(true, "127.0.0.1:7331", &fingerprint)
            .expect("valid loopback listener config");
        assert_eq!(config.listen_address.to_string(), "127.0.0.1:7331");
        assert_eq!(config.peer_fingerprint, [0xab; 32]);

        assert!(validate_config(true, "localhost:7331", &fingerprint).is_err());
        assert!(validate_config(true, "127.0.0.1:7331", "ab").is_err());
    }
}
