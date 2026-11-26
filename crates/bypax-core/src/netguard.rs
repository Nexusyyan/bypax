use crate::model::NetworkSnapshot;
use anyhow::Result;
use std::path::{Path, PathBuf};

pub const DEFAULT_BYPASS_LIST: &str =
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

/// Abstraction over OS system proxy and DNS controls so crash-recovery rollback
/// can be verified deterministically in tests without mutating the developer's host OS.
pub trait SystemNetworkAdapter: Send + Sync {
    fn capture_snapshot(&self) -> Result<NetworkSnapshot>;
    fn apply_system_proxy(&self, host: &str, port: u16, bypass: &str) -> Result<()>;
    fn restore_snapshot(&self, snapshot: &NetworkSnapshot) -> Result<()>;
}

/// Transactional OS proxy/DNS guard with disk-persisted crash recovery.
pub struct NetGuard<A: SystemNetworkAdapter = OsNetworkAdapter> {
    snapshot_file: PathBuf,
    adapter: A,
}

impl NetGuard<OsNetworkAdapter> {
    pub fn new(runtime_dir: &Path) -> Self {
        Self::with_adapter(runtime_dir, OsNetworkAdapter)
    }
}

impl<A: SystemNetworkAdapter> NetGuard<A> {
    pub fn with_adapter(runtime_dir: &Path, adapter: A) -> Self {
        let _ = std::fs::create_dir_all(runtime_dir);
        Self {
            snapshot_file: runtime_dir.join("netguard-snapshot.json"),
            adapter,
        }
    }

    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_file
    }

    pub fn load_persisted_snapshot(&self) -> Option<NetworkSnapshot> {
        let raw = std::fs::read_to_string(&self.snapshot_file).ok()?;
        serde_json::from_str(&raw).ok()
    }

    pub fn is_armed(&self) -> bool {
        self.load_persisted_snapshot()
            .map(|s| s.active_sentinel)
            .unwrap_or(false)
    }

    /// Cold-start recovery: if a previous session crashed while system proxy/TUN
    /// was active, restore the pre-activation OS settings cleanly.
    pub fn recover_if_dirty(&self) -> Result<bool> {
        let Some(snapshot) = self.load_persisted_snapshot() else {
            return Ok(false);
        };
        if !snapshot.active_sentinel {
            return Ok(false);
        }
        self.adapter.restore_snapshot(&snapshot)?;
        let _ = std::fs::remove_file(&self.snapshot_file);
        Ok(true)
    }

    /// Captures current OS proxy/DNS snapshot to disk BEFORE enabling proxy.
    pub fn enable_system_proxy(&self, host: &str, port: u16) -> Result<NetworkSnapshot> {
        let snapshot = if let Some(existing) = self.load_persisted_snapshot() {
            if existing.active_sentinel {
                existing
            } else {
                let mut fresh = self.adapter.capture_snapshot()?;
                fresh.active_sentinel = true;
                self.persist_snapshot(&fresh)?;
                fresh
            }
        } else {
            let mut fresh = self.adapter.capture_snapshot()?;
            fresh.active_sentinel = true;
            self.persist_snapshot(&fresh)?;
            fresh
        };

        self.adapter
            .apply_system_proxy(host, port, DEFAULT_BYPASS_LIST)?;
        Ok(snapshot)
    }

    /// Restores the original OS proxy/DNS snapshot and removes the crash sentinel.
    pub fn disable_system_proxy(&self) -> Result<bool> {
        if let Some(snapshot) = self.load_persisted_snapshot() {
            self.adapter.restore_snapshot(&snapshot)?;
            let _ = std::fs::remove_file(&self.snapshot_file);
            Ok(true)
        } else {
            // Even without a snapshot, explicitly turn off proxy safely.
            let clean = NetworkSnapshot {
                platform: std::env::consts::OS.to_string(),
                proxy_enable: false,
                proxy_server: String::new(),
                proxy_override: String::new(),
                dns_servers: Vec::new(),
                captured_at: chrono::Utc::now().to_rfc3339(),
                active_sentinel: false,
                macos_services: Vec::new(),
            };
            self.adapter.restore_snapshot(&clean)?;
            Ok(false)
        }
    }

    fn persist_snapshot(&self, snapshot: &NetworkSnapshot) -> Result<()> {
        if let Some(parent) = self.snapshot_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.snapshot_file.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(snapshot)?)?;
        std::fs::rename(&tmp, &self.snapshot_file)?;
        Ok(())
    }
}

pub struct OsNetworkAdapter;

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use anyhow::anyhow;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_SZ, REG_VALUE_TYPE,
    };

    const INTERNET_SETTINGS_SUBKEY: &str =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

    fn to_wide_null(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    fn read_reg_dword(key: HKEY, name: &str) -> u32 {
        let wname = to_wide_null(name);
        let mut data: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        let mut ty = REG_VALUE_TYPE(0);
        unsafe {
            let status = RegQueryValueExW(
                key,
                PCWSTR(wname.as_ptr()),
                None,
                Some(&mut ty),
                Some(&mut data as *mut u32 as *mut u8),
                Some(&mut size),
            );
            if status.is_ok() {
                data
            } else {
                0
            }
        }
    }

    fn read_reg_string(key: HKEY, name: &str) -> String {
        let wname = to_wide_null(name);
        let mut size: u32 = 0;
        let mut ty = REG_VALUE_TYPE(0);
        unsafe {
            if RegQueryValueExW(key, PCWSTR(wname.as_ptr()), None, Some(&mut ty), None, Some(&mut size))
                .is_err()
                || size < 2
            {
                return String::new();
            }
            let mut buf: Vec<u16> = vec![0; (size as usize) / 2];
            if RegQueryValueExW(
                key,
                PCWSTR(wname.as_ptr()),
                None,
                Some(&mut ty),
                Some(buf.as_mut_ptr() as *mut u8),
                Some(&mut size),
            )
            .is_err()
            {
                return String::new();
            }
            while buf.last() == Some(&0) {
                buf.pop();
            }
            String::from_utf16_lossy(&buf)
        }
    }

    fn write_reg_dword(key: HKEY, name: &str, value: u32) -> Result<()> {
        let wname = to_wide_null(name);
        let bytes = value.to_le_bytes();
        unsafe {
            RegSetValueExW(key, PCWSTR(wname.as_ptr()), 0, REG_DWORD, Some(&bytes))
                .ok()
                .map_err(|e| anyhow!("RegSetValueExW({}) failed: {}", name, e))?;
        }
        Ok(())
    }

    fn write_reg_string(key: HKEY, name: &str, value: &str) -> Result<()> {
        let wname = to_wide_null(name);
        let wval = to_wide_null(value);
        let bytes = unsafe {
            std::slice::from_raw_parts(wval.as_ptr() as *const u8, wval.len() * 2)
        };
        unsafe {
            RegSetValueExW(key, PCWSTR(wname.as_ptr()), 0, REG_SZ, Some(bytes))
                .ok()
                .map_err(|e| anyhow!("RegSetValueExW({}) failed: {}", name, e))?;
        }
        Ok(())
    }

    fn notify_wininet() {
        unsafe {
            let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
            let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
        }
    }

    impl SystemNetworkAdapter for OsNetworkAdapter {
        fn capture_snapshot(&self) -> Result<NetworkSnapshot> {
            let subkey = to_wide_null(INTERNET_SETTINGS_SUBKEY);
            let mut hkey = HKEY::default();
            unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(subkey.as_ptr()),
                    0,
                    KEY_READ,
                    &mut hkey,
                )
                .ok()
                .map_err(|e| anyhow!("RegOpenKeyExW(read) failed: {}", e))?;
            }
            let proxy_enable = read_reg_dword(hkey, "ProxyEnable") != 0;
            let proxy_server = read_reg_string(hkey, "ProxyServer");
            let proxy_override = read_reg_string(hkey, "ProxyOverride");
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            Ok(NetworkSnapshot {
                platform: "windows".to_string(),
                proxy_enable,
                proxy_server,
                proxy_override,
                dns_servers: Vec::new(),
                captured_at: chrono::Utc::now().to_rfc3339(),
                active_sentinel: false,
                macos_services: Vec::new(),
            })
        }

        fn apply_system_proxy(&self, host: &str, port: u16, bypass: &str) -> Result<()> {
            let subkey = to_wide_null(INTERNET_SETTINGS_SUBKEY);
            let mut hkey = HKEY::default();
            unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(subkey.as_ptr()),
                    0,
                    KEY_SET_VALUE,
                    &mut hkey,
                )
                .ok()
                .map_err(|e| anyhow!("RegOpenKeyExW(write) failed: {}", e))?;
            }
            let addr = format!("{}:{}", host, port);
            let res = write_reg_dword(hkey, "ProxyEnable", 1)
                .and_then(|_| write_reg_string(hkey, "ProxyServer", &addr))
                .and_then(|_| write_reg_string(hkey, "ProxyOverride", bypass));
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            notify_wininet();
            res
        }

        fn restore_snapshot(&self, snapshot: &NetworkSnapshot) -> Result<()> {
            let subkey = to_wide_null(INTERNET_SETTINGS_SUBKEY);
            let mut hkey = HKEY::default();
            unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(subkey.as_ptr()),
                    0,
                    KEY_SET_VALUE,
                    &mut hkey,
                )
                .ok()
                .map_err(|e| anyhow!("RegOpenKeyExW(restore) failed: {}", e))?;
            }
            let res = write_reg_dword(hkey, "ProxyEnable", if snapshot.proxy_enable { 1 } else { 0 })
                .and_then(|_| write_reg_string(hkey, "ProxyServer", &snapshot.proxy_server))
                .and_then(|_| write_reg_string(hkey, "ProxyOverride", &snapshot.proxy_override));
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            notify_wininet();
            res
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use crate::model::MacOsServiceSnapshot;
    use std::process::Command;

    const MACOS_DEFAULT_BYPASS: &[&str] = &[
        "127.0.0.1",
        "localhost",
        "*.local",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "198.19.0.0/16",
    ];

    fn is_virtual_macos_service(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower.contains("bluetooth")
            || lower.contains("thunderbolt bridge")
            || lower.contains("iphone usb")
            || lower.contains("ipad usb")
            || lower.contains("utun")
            || lower.contains("vpn")
            || lower.contains("tailscale")
            || lower.contains("orbstack")
            || lower.contains("wireguard")
            || lower.contains("docker")
    }

    fn enabled_macos_network_services() -> Vec<String> {
        let out = Command::new("networksetup")
            .arg("-listallnetworkservices")
            .output();
        let mut services = Vec::new();
        if let Ok(o) = out {
            let text = String::from_utf8_lossy(&o.stdout);
            for line in text.lines().skip(1) {
                let s = line.trim();
                if !s.is_empty() && !s.starts_with('*') && !is_virtual_macos_service(s) {
                    services.push(s.to_string());
                }
            }
        }
        if services.is_empty() {
            services.push("Wi-Fi".to_string());
        }
        services
    }

    fn parse_proxy_output(text: &str) -> (bool, String, u16) {
        let mut enabled = false;
        let mut server = String::new();
        let mut port = 0u16;
        for line in text.lines() {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim();
                let val = v.trim();
                match key {
                    "Enabled" => enabled = val.eq_ignore_ascii_case("yes"),
                    "Server" => server = val.to_string(),
                    "Port" => port = val.parse::<u16>().unwrap_or(0),
                    _ => {}
                }
            }
        }
        (enabled, server, port)
    }

    fn query_proxy_state(flag: &str, svc: &str) -> (bool, String, u16) {
        let text = Command::new("networksetup")
            .args([flag, svc])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        parse_proxy_output(&text)
    }

    fn snapshot_single_service(svc: &str) -> MacOsServiceSnapshot {
        let (web_enabled, web_server, web_port) = query_proxy_state("-getwebproxy", svc);
        let (secure_web_enabled, secure_web_server, secure_web_port) =
            query_proxy_state("-getsecurewebproxy", svc);
        let (socks_enabled, socks_server, socks_port) =
            query_proxy_state("-getsocksfirewallproxy", svc);

        let bypass_out = Command::new("networksetup")
            .args(["-getproxybypassdomains", svc])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let bypass_domains: Vec<String> = bypass_out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.contains("aren't any"))
            .collect();

        let dns_out = Command::new("networksetup")
            .args(["-getdnsservers", svc])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let dns_servers: Vec<String> = dns_out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.contains("aren't any"))
            .collect();

        MacOsServiceSnapshot {
            service_name: svc.to_string(),
            web_enabled,
            web_server,
            web_port,
            secure_web_enabled,
            secure_web_server,
            secure_web_port,
            socks_enabled,
            socks_server,
            socks_port,
            bypass_domains,
            dns_servers,
        }
    }

    fn restore_single_service(svc_snap: &MacOsServiceSnapshot) {
        let svc = &svc_snap.service_name;
        if svc_snap.web_enabled && !svc_snap.web_server.is_empty() && svc_snap.web_port > 0 {
            let p = svc_snap.web_port.to_string();
            let _ = Command::new("networksetup")
                .args(["-setwebproxy", svc, &svc_snap.web_server, &p])
                .status();
            let _ = Command::new("networksetup")
                .args(["-setwebproxystate", svc, "on"])
                .status();
        } else {
            let _ = Command::new("networksetup")
                .args(["-setwebproxystate", svc, "off"])
                .status();
        }

        if svc_snap.secure_web_enabled
            && !svc_snap.secure_web_server.is_empty()
            && svc_snap.secure_web_port > 0
        {
            let p = svc_snap.secure_web_port.to_string();
            let _ = Command::new("networksetup")
                .args(["-setsecurewebproxy", svc, &svc_snap.secure_web_server, &p])
                .status();
            let _ = Command::new("networksetup")
                .args(["-setsecurewebproxystate", svc, "on"])
                .status();
        } else {
            let _ = Command::new("networksetup")
                .args(["-setsecurewebproxystate", svc, "off"])
                .status();
        }

        if svc_snap.socks_enabled && !svc_snap.socks_server.is_empty() && svc_snap.socks_port > 0 {
            let p = svc_snap.socks_port.to_string();
            let _ = Command::new("networksetup")
                .args(["-setsocksfirewallproxy", svc, &svc_snap.socks_server, &p])
                .status();
            let _ = Command::new("networksetup")
                .args(["-setsocksfirewallproxystate", svc, "on"])
                .status();
        } else {
            let _ = Command::new("networksetup")
                .args(["-setsocksfirewallproxystate", svc, "off"])
                .status();
        }

        if svc_snap.bypass_domains.is_empty() {
            let _ = Command::new("networksetup")
                .args(["-setproxybypassdomains", svc, "Empty"])
                .status();
        } else {
            let mut args = vec!["-setproxybypassdomains".to_string(), svc.clone()];
            args.extend(svc_snap.bypass_domains.clone());
            let _ = Command::new("networksetup").args(args).status();
        }

        if svc_snap.dns_servers.is_empty() {
            let _ = Command::new("networksetup")
                .args(["-setdnsservers", svc, "Empty"])
                .status();
        } else {
            let mut args = vec!["-setdnsservers".to_string(), svc.clone()];
            args.extend(svc_snap.dns_servers.clone());
            let _ = Command::new("networksetup").args(args).status();
        }
    }

    impl SystemNetworkAdapter for OsNetworkAdapter {
        fn capture_snapshot(&self) -> Result<NetworkSnapshot> {
            let services = enabled_macos_network_services();
            let macos_services: Vec<MacOsServiceSnapshot> = services
                .iter()
                .map(|s| snapshot_single_service(s))
                .collect();
            let primary = macos_services.first();
            Ok(NetworkSnapshot {
                platform: format!(
                    "macos:{}",
                    primary
                        .map(|s| s.service_name.as_str())
                        .unwrap_or("Wi-Fi")
                ),
                proxy_enable: primary
                    .map(|s| s.web_enabled || s.secure_web_enabled || s.socks_enabled)
                    .unwrap_or(false),
                proxy_server: primary.map(|s| s.web_server.clone()).unwrap_or_default(),
                proxy_override: primary
                    .map(|s| s.bypass_domains.join(";"))
                    .unwrap_or_default(),
                dns_servers: primary.map(|s| s.dns_servers.clone()).unwrap_or_default(),
                captured_at: chrono::Utc::now().to_rfc3339(),
                active_sentinel: false,
                macos_services,
            })
        }

        fn apply_system_proxy(&self, host: &str, port: u16, _bypass: &str) -> Result<()> {
            let services = enabled_macos_network_services();
            let port_s = port.to_string();
            for svc in &services {
                let _ = Command::new("networksetup")
                    .args(["-setwebproxy", svc, host, &port_s])
                    .status();
                let _ = Command::new("networksetup")
                    .args(["-setsecurewebproxy", svc, host, &port_s])
                    .status();
                let _ = Command::new("networksetup")
                    .args(["-setsocksfirewallproxy", svc, host, &port_s])
                    .status();
                let mut bypass_args = vec!["-setproxybypassdomains".to_string(), svc.clone()];
                bypass_args.extend(MACOS_DEFAULT_BYPASS.iter().map(|s| (*s).to_string()));
                let _ = Command::new("networksetup").args(bypass_args).status();
            }
            Ok(())
        }

        fn restore_snapshot(&self, snapshot: &NetworkSnapshot) -> Result<()> {
            if !snapshot.macos_services.is_empty() {
                for svc_snap in &snapshot.macos_services {
                    restore_single_service(svc_snap);
                }
                return Ok(());
            }
            for svc in enabled_macos_network_services() {
                restore_single_service(&MacOsServiceSnapshot {
                    service_name: svc,
                    dns_servers: snapshot.dns_servers.clone(),
                    ..Default::default()
                });
            }
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod platform {
    use super::*;
    use std::process::Command;

    impl SystemNetworkAdapter for OsNetworkAdapter {
        fn capture_snapshot(&self) -> Result<NetworkSnapshot> {
            let mode = Command::new("gsettings")
                .args(["get", "org.gnome.system.proxy", "mode"])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            Ok(NetworkSnapshot {
                platform: "linux".to_string(),
                proxy_enable: mode.contains("manual"),
                proxy_server: String::new(),
                proxy_override: String::new(),
                dns_servers: Vec::new(),
                captured_at: chrono::Utc::now().to_rfc3339(),
                active_sentinel: false,
                macos_services: Vec::new(),
            })
        }

        fn apply_system_proxy(&self, host: &str, port: u16, _bypass: &str) -> Result<()> {
            let port_s = port.to_string();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "manual"])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.http", "host", host])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.http", "port", &port_s])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.https", "host", host])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.https", "port", &port_s])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.socks", "host", host])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.socks", "port", &port_s])
                .status();
            Ok(())
        }

        fn restore_snapshot(&self, snapshot: &NetworkSnapshot) -> Result<()> {
            let mode = if snapshot.proxy_enable { "manual" } else { "none" };
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", mode])
                .status();
            Ok(())
        }
    }
}
