use tauri::image::Image;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::window::Color;
use tauri::{
    AppHandle, Emitter, Manager, PhysicalPosition, WebviewUrl, WebviewWindowBuilder, WindowEvent,
};

pub const TRAY_ID: &str = "bypax-tray";
pub const TRAY_POPUP_LABEL: &str = "tray-popup";
const POPUP_LOGICAL_W: f64 = 304.0;
const POPUP_LOGICAL_H: f64 = 456.0;

// Canonical surface backgrounds from DESIGN.md (prevents white flash on WebView2 dark theme).
const MAIN_BG_LIGHT: Color = Color(0xF6, 0xF7, 0xF9, 0xFF);
const MAIN_BG_DARK: Color = Color(0x0B, 0x11, 0x20, 0xFF);
const POPUP_BG_LIGHT: Color = Color(0xFF, 0xFF, 0xFF, 0xFF);
const POPUP_BG_DARK: Color = Color(0x16, 0x1B, 0x22, 0xFF);

#[cfg(target_os = "macos")]
const TRAY_TEMPLATE_IDLE: &[u8] = include_bytes!("../icons/tray-template.png");
#[cfg(target_os = "macos")]
const TRAY_TEMPLATE_ACTIVE: &[u8] = include_bytes!("../icons/tray-template-active.png");
#[cfg(target_os = "macos")]
const TRAY_TEMPLATE_WARN: &[u8] = include_bytes!("../icons/tray-template-warn.png");

#[cfg(not(target_os = "macos"))]
const TRAY_LIGHT_IDLE: &[u8] = include_bytes!("../icons/tray-light.png");
#[cfg(not(target_os = "macos"))]
const TRAY_LIGHT_ACTIVE: &[u8] = include_bytes!("../icons/tray-light-active.png");
#[cfg(not(target_os = "macos"))]
const TRAY_LIGHT_WARN: &[u8] = include_bytes!("../icons/tray-light-warn.png");

#[cfg(not(target_os = "macos"))]
const TRAY_DARK_IDLE: &[u8] = include_bytes!("../icons/tray-dark.png");
#[cfg(not(target_os = "macos"))]
const TRAY_DARK_ACTIVE: &[u8] = include_bytes!("../icons/tray-dark-active.png");
#[cfg(not(target_os = "macos"))]
const TRAY_DARK_WARN: &[u8] = include_bytes!("../icons/tray-dark-warn.png");

pub fn resolve_theme_is_dark(theme: &str) -> bool {
    match theme.trim().to_ascii_lowercase().as_str() {
        "dark" => true,
        "light" => false,
        _ => is_system_app_dark(),
    }
}

#[cfg(target_os = "windows")]
fn read_personalize_dword(value_name: &str) -> Option<u32> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ, REG_DWORD,
        REG_VALUE_TYPE,
    };

    let subkey: Vec<u16> =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\0"
            .encode_utf16()
            .collect();
    let val_name: Vec<u16> = format!("{}\0", value_name).encode_utf16().collect();

    unsafe {
        let mut hkey = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );
        if status.is_err() {
            return None;
        }
        let mut data: u32 = 1;
        let mut data_len = std::mem::size_of::<u32>() as u32;
        let mut reg_type = REG_VALUE_TYPE(0);
        let q = RegQueryValueExW(
            hkey,
            PCWSTR(val_name.as_ptr()),
            None,
            Some(&mut reg_type),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut data_len),
        );
        let _ = RegCloseKey(hkey);
        if q.is_ok() && reg_type == REG_DWORD {
            Some(data)
        } else {
            None
        }
    }
}

#[cfg(target_os = "windows")]
fn is_system_app_dark() -> bool {
    read_personalize_dword("AppsUseLightTheme")
        .map(|v| v == 0)
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn is_system_taskbar_dark() -> bool {
    read_personalize_dword("SystemUsesLightTheme")
        .map(|v| v == 0)
        .unwrap_or(true)
}

#[cfg(target_os = "macos")]
fn is_system_app_dark() -> bool {
    std::process::Command::new("defaults")
        .args(["read", "-g", "AppleInterfaceStyle"])
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .eq_ignore_ascii_case("Dark")
        })
        .unwrap_or(false)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn is_system_app_dark() -> bool {
    false
}

#[cfg(all(unix, not(target_os = "macos")))]
fn is_system_taskbar_dark() -> bool {
    true
}

fn current_saved_theme(app: &AppHandle) -> String {
    app.try_state::<crate::state::AppState>()
        .and_then(|st| st.store.lock().ok().and_then(|s| s.load_settings().ok()))
        .map(|s| s.theme)
        .unwrap_or_else(|| "system".to_string())
}

pub fn sync_window_background_colors(app: &AppHandle, theme: &str) {
    let is_dark = resolve_theme_is_dark(theme);
    let main_color = if is_dark { MAIN_BG_DARK } else { MAIN_BG_LIGHT };
    let popup_color = if is_dark {
        POPUP_BG_DARK
    } else {
        POPUP_BG_LIGHT
    };
    if let Some(main_win) = app.get_webview_window("main") {
        let _ = main_win.set_background_color(Some(main_color));
    }
    if let Some(popup_win) = app.get_webview_window(TRAY_POPUP_LABEL) {
        let _ = popup_win.set_background_color(Some(popup_color));
    }
}

fn load_tray_icon(active: bool, warn: bool) -> Option<(Image<'static>, bool)> {
    #[cfg(target_os = "macos")]
    {
        let (bytes, as_template) = if warn {
            (TRAY_TEMPLATE_WARN, false)
        } else if active {
            (TRAY_TEMPLATE_ACTIVE, false)
        } else {
            (TRAY_TEMPLATE_IDLE, true)
        };
        Image::from_bytes(bytes).ok().map(|img| (img, as_template))
    }

    #[cfg(not(target_os = "macos"))]
    {
        let dark_bar = is_system_taskbar_dark();
        let bytes = match (dark_bar, warn, active) {
            (true, true, _) => TRAY_DARK_WARN,
            (true, false, true) => TRAY_DARK_ACTIVE,
            (true, false, false) => TRAY_DARK_IDLE,
            (false, true, _) => TRAY_LIGHT_WARN,
            (false, false, true) => TRAY_LIGHT_ACTIVE,
            (false, false, false) => TRAY_LIGHT_IDLE,
        };
        Image::from_bytes(bytes).ok().map(|img| (img, false))
    }
}

pub fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let saved_theme = current_saved_theme(app);
    sync_window_background_colors(app, &saved_theme);

    // Pre-create hidden custom tray popover window so opening is instantaneous.
    let _ = ensure_tray_popup(app);

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Bypax")
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| match event {
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } => {
                hide_tray_popup(tray.app_handle());
                toggle_main_window(tray.app_handle());
            }
            TrayIconEvent::Click {
                button: MouseButton::Right,
                button_state: MouseButtonState::Up,
                position,
                ..
            } => {
                toggle_tray_popup(tray.app_handle(), position);
            }
            _ => {}
        });

    if let Some((icon, as_template)) = load_tray_icon(false, false) {
        builder = builder.icon(icon);
        #[cfg(target_os = "macos")]
        {
            builder = builder.icon_as_template(as_template);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = as_template;
        }
    } else if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }

    builder.build(app)?;
    Ok(())
}

fn ensure_tray_popup(app: &AppHandle) -> tauri::Result<tauri::WebviewWindow> {
    if let Some(existing) = app.get_webview_window(TRAY_POPUP_LABEL) {
        return Ok(existing);
    }
    let is_dark = resolve_theme_is_dark(&current_saved_theme(app));
    let popup_bg = if is_dark {
        POPUP_BG_DARK
    } else {
        POPUP_BG_LIGHT
    };

    let popup = WebviewWindowBuilder::new(
        app,
        TRAY_POPUP_LABEL,
        WebviewUrl::App("index.html?view=tray".into()),
    )
    .title("Bypax Tray")
    .inner_size(POPUP_LOGICAL_W, POPUP_LOGICAL_H)
    .background_color(popup_bg)
    .resizable(false)
    .decorations(false)
    .shadow(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .visible(false)
    .build()?;

    let handle = app.clone();
    popup.on_window_event(move |event| match event {
        WindowEvent::Focused(false) => {
            if let Some(w) = handle.get_webview_window(TRAY_POPUP_LABEL) {
                let _ = w.hide();
            }
        }
        WindowEvent::CloseRequested { api, .. } => {
            api.prevent_close();
            if let Some(w) = handle.get_webview_window(TRAY_POPUP_LABEL) {
                let _ = w.hide();
            }
        }
        _ => {}
    });

    Ok(popup)
}

fn toggle_tray_popup(app: &AppHandle, click_pos: PhysicalPosition<f64>) {
    let Ok(popup) = ensure_tray_popup(app) else {
        return;
    };
    if popup.is_visible().unwrap_or(false) {
        let _ = popup.hide();
        return;
    }

    // Position popup anchored neatly above (or below) the taskbar tray icon within monitor bounds.
    let monitor = app
        .available_monitors()
        .ok()
        .and_then(|list| {
            list.into_iter().find(|m| {
                let pos = m.position();
                let size = m.size();
                click_pos.x >= pos.x as f64
                    && click_pos.x <= (pos.x + size.width as i32) as f64
                    && click_pos.y >= pos.y as f64
                    && click_pos.y <= (pos.y + size.height as i32) as f64
            })
        })
        .or_else(|| popup.current_monitor().ok().flatten())
        .or_else(|| app.primary_monitor().ok().flatten());

    if let Some(mon) = monitor {
        let scale = mon.scale_factor();
        let work = mon.work_area();
        let margin = (10.0 * scale).round() as i32;
        let pop_w = (POPUP_LOGICAL_W * scale).round() as i32;
        let pop_h = (POPUP_LOGICAL_H * scale).round() as i32;

        let min_x = work.position.x + margin;
        let max_x = (work.position.x + work.size.width as i32 - pop_w - margin).max(min_x);
        let desired_x = click_pos.x.round() as i32 - pop_w / 2;
        let x = desired_x.clamp(min_x, max_x);

        let min_y = work.position.y + margin;
        let max_y = (work.position.y + work.size.height as i32 - pop_h - margin).max(min_y);
        let mid_y = work.position.y + (work.size.height as i32) / 2;
        let desired_y = if (click_pos.y as i32) >= mid_y {
            max_y.min(click_pos.y.round() as i32 - pop_h - margin)
        } else {
            min_y.max(click_pos.y.round() as i32 + margin)
        };
        let y = desired_y.clamp(min_y, max_y);
        let _ = popup.set_position(PhysicalPosition::new(x, y));
    }

    let _ = app.emit("bypax-state-sync", ());
    let _ = popup.show();
    let _ = popup.unminimize();
    let _ = popup.set_focus();
}

pub fn hide_tray_popup(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(TRAY_POPUP_LABEL) {
        let _ = w.hide();
    }
}

pub fn show_main_window(app: &AppHandle) {
    hide_tray_popup(app);
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

pub fn toggle_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let visible = win.is_visible().unwrap_or(false);
        let minimized = win.is_minimized().unwrap_or(false);
        if visible && !minimized {
            let _ = win.hide();
        } else {
            let _ = win.show();
            let _ = win.unminimize();
            let _ = win.set_focus();
        }
    }
}

pub fn update_tray_tooltip(app: &AppHandle, text: &str) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(text));
    }
}

pub fn update_tray_icon_state(app: &AppHandle, active: bool, warn: bool) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        if let Some((icon, as_template)) = load_tray_icon(active, warn) {
            let _ = tray.set_icon(Some(icon));
            #[cfg(target_os = "macos")]
            {
                let _ = tray.set_icon_as_template(as_template);
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = as_template;
            }
        }
    }
}
