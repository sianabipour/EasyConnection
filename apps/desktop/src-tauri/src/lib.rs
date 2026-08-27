mod commands;

use std::sync::Arc;

use rt_core::{init_logging, AppController};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};

pub fn run() {
    init_logging("info");

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let controller = Arc::new(AppController::bootstrap().map_err(|e| e.to_string())?);
            app.manage(controller);

            let show = MenuItem::with_id(app, "show", "Show Easy Connection", true, None::<&str>)?;
            let disconnect =
                MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &disconnect, &quit])?;

            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "disconnect" => {
                        let ctrl = app.state::<Arc<AppController>>().inner().clone();
                        tauri::async_runtime::spawn(async move {
                            let _ = ctrl.disconnect().await;
                        });
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                });
            if let Some(icon) = app.default_window_icon().cloned() {
                tray = tray.icon(icon);
            }
            let _ = tray.build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_profiles,
            commands::add_ssh_profile,
            commands::add_ss_profile,
            commands::add_vless_profile,
            commands::get_profile,
            commands::update_ssh_profile,
            commands::delete_profile,
            commands::connect_profile,
            commands::disconnect,
            commands::connection_status,
            commands::get_app_settings,
            commands::set_preferred_routing_mode,
            commands::emergency_restore,
            commands::leak_report,
            commands::import_profile,
            commands::tcp_probe,
            commands::traceroute,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Easy Connection");
}
