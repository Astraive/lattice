mod encoding;
mod identity;
mod profile;
mod spaces;

/// Starts the native Lattice desktop process.
///
/// # Panics
///
/// Panics when Tauri cannot initialize the configured application runtime.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            identity::initialize_device_identity,
            identity::get_device_identity,
            identity::get_device_certificate_signing_request,
            spaces::list_local_spaces,
            spaces::create_local_space,
            spaces::queue_local_text_message,
            spaces::list_local_text_messages,
            identity::pin_peer_identity,
            identity::get_pinned_identity
        ])
        .run(tauri::generate_context!())
        .expect("failed to run the Lattice desktop application");
}
