mod attachments;
mod encoding;

mod identity;
mod local_network;
mod profile;
mod relay_settings;

mod spaces;

/// Starts the native Lattice desktop process.
///
/// # Panics
///
/// Panics when Tauri cannot initialize the configured application runtime.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            identity::initialize_device_identity,
            identity::get_device_identity,
            identity::get_device_certificate_signing_request,
            spaces::list_local_spaces,
            spaces::recover_local_space_generation,
            spaces::create_local_space,
            spaces::import_local_space_welcome_bootstrap,
            spaces::queue_local_text_message,
            spaces::queue_local_text_message_edit,
            spaces::list_local_text_messages,
            attachments::queue_local_file_attachment,
            attachments::list_local_attachment_sources,
            attachments::remove_local_attachment_source,
            spaces::search_local_text_messages,
            identity::pin_peer_identity,
            identity::get_pinned_identity,
            identity::unpin_peer_identity,
            local_network::scan_local_path_capabilities,
            relay_settings::list_local_relays,
            relay_settings::add_local_relay,
            relay_settings::remove_local_relay
        ])
        .run(tauri::generate_context!())
        .expect("failed to run the Lattice desktop application");
}
