use tauri::Manager as _;

mod attachments;
mod peer_mode;

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
    let peer_mode_state = peer_mode::PeerModeState::load();
    let autostart = peer_mode_state.clone();
    let app = tauri::Builder::default()
        .manage(peer_mode_state)
        .setup(move |_| {
            if autostart.should_autostart() {
                let autostart = autostart.clone();
                tauri::async_runtime::spawn(async move {
                    autostart.autostart().await;
                });
            }
            Ok(())
        })
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
            attachments::send_authorized_attachment_once,
            attachments::receive_authorized_attachment_once,
            spaces::search_local_text_messages,
            identity::pin_peer_identity,
            identity::get_pinned_identity,
            identity::unpin_peer_identity,
            local_network::scan_local_path_capabilities,
            local_network::discover_local_lan_endpoints,
            relay_settings::list_local_relays,
            relay_settings::add_local_relay,
            relay_settings::remove_local_relay,
            peer_mode::get_persistent_peer_mode_status,
            peer_mode::configure_persistent_peer_mode,
            peer_mode::list_retained_courier_items,
            peer_mode::forward_queued_courier_item
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the Lattice desktop application");
    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::Exit)
            && let Some(state) = app_handle.try_state::<peer_mode::PeerModeState>()
        {
            state.cancel_on_exit();
        }
    });
}
