use crate::process::ProcessTracker;
use anyhow::{anyhow, Result};
use bypax_core::model::AppProxyRule;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Static definition of a cross-platform built-in application preset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPresetDef {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub process_names: Vec<String>,
    pub path_contains: Vec<String>,
    pub mac_bundle_paths: Vec<String>,
    pub include_children: bool,
}

/// Live preset card payload combining static preset metadata, OS installation/process detection,
/// and current user rule state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPresetStatus {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub process_names: Vec<String>,
    pub path_contains: Vec<String>,
    pub mac_bundle_paths: Vec<String>,
    pub include_children: bool,
    pub installed: bool,
    pub running_count: usize,
    pub detected_paths: Vec<String>,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub target: String,
}

/// Returns all 7 cross-platform built-in application presets in canonical UI display order.
pub fn list_app_presets() -> Vec<AppPresetDef> {
    vec![
        AppPresetDef {
            id: "antigravity".into(),
            name: "Antigravity".into(),
            category: "AI & IDE".into(),
            description:
                "Antigravity IDE, language server, and spawned MCP/CLI child processes.".into(),
            process_names: vec![
                "Antigravity.exe".into(),
                "language_server.exe".into(),
                "language_server_windows_x64.exe".into(),
                "ls_core.exe".into(),
                "Antigravity".into(),
                "language_server_macos_arm".into(),
                "language_server_macos_x64".into(),
            ],
            path_contains: vec!["Antigravity".into()],
            mac_bundle_paths: vec!["/Applications/Antigravity.app".into()],
            include_children: true,
        },
        AppPresetDef {
            id: "cursor".into(),
            name: "Cursor".into(),
            category: "AI & IDE".into(),
            description: "Cursor editor, extension host, and spawned AI subprocesses.".into(),
            process_names: vec!["Cursor.exe".into(), "Cursor".into()],
            path_contains: vec!["cursor".into()],
            mac_bundle_paths: vec!["/Applications/Cursor.app".into()],
            include_children: true,
        },
        AppPresetDef {
            id: "vscode".into(),
            name: "VS Code".into(),
            category: "AI & IDE".into(),
            description: "Visual Studio Code, extension host, and remote CLI workers.".into(),
            process_names: vec!["Code.exe".into(), "Electron".into()],
            path_contains: vec!["Microsoft VS Code".into(), "Visual Studio Code".into()],
            mac_bundle_paths: vec!["/Applications/Visual Studio Code.app".into()],
            include_children: true,
        },
        AppPresetDef {
            id: "git".into(),
            name: "Git & SSH".into(),
            category: "Developer".into(),
            description: "Git, git-remote-https, OpenSSH, and curl CLI operations.".into(),
            process_names: vec![
                "git.exe".into(),
                "git-remote-https.exe".into(),
                "ssh.exe".into(),
                "curl.exe".into(),
                "git".into(),
                "git-remote-https".into(),
                "ssh".into(),
                "curl".into(),
            ],
            path_contains: vec![],
            mac_bundle_paths: vec![],
            include_children: true,
        },
        AppPresetDef {
            id: "discord".into(),
            name: "Discord".into(),
            category: "Messaging".into(),
            description: "Discord desktop client, updater, and voice/gateway subprocesses.".into(),
            process_names: vec!["Discord.exe".into(), "Discord".into()],
            path_contains: vec!["Discord".into()],
            mac_bundle_paths: vec!["/Applications/Discord.app".into()],
            include_children: true,
        },
        AppPresetDef {
            id: "telegram".into(),
            name: "Telegram".into(),
            category: "Messaging".into(),
            description: "Telegram Desktop native client.".into(),
            process_names: vec!["Telegram.exe".into(), "Telegram".into()],
            path_contains: vec!["Telegram".into()],
            mac_bundle_paths: vec!["/Applications/Telegram.app".into()],
            include_children: true,
        },
        AppPresetDef {
            id: "steam".into(),
            name: "Steam".into(),
            category: "Gaming".into(),
            description: "Steam client, steamwebhelper, and game launcher subprocesses.".into(),
            process_names: vec![
                "steam.exe".into(),
                "steamwebhelper.exe".into(),
                "steam_osx".into(),
            ],
            path_contains: vec!["Steam".into()],
            mac_bundle_paths: vec!["/Applications/Steam.app".into()],
            include_children: true,
        },
    ]
}

/// Converts a built-in preset ID into a persisted `AppProxyRule`.
pub fn preset_to_rule(preset_id: &str, target: &str, priority: i32) -> Result<AppProxyRule> {
    let key = preset_id.trim().to_ascii_lowercase();
    let preset = list_app_presets()
        .into_iter()
        .find(|p| p.id == key)
        .ok_or_else(|| anyhow!("unknown preset '{key}'"))?;

    let clean_target = if target.trim().is_empty() {
        "follow".to_string()
    } else {
        target.trim().to_string()
    };

    Ok(AppProxyRule {
        id: format!("preset-{}", preset.id),
        name: preset.name,
        enabled: true,
        priority,
        preset_id: Some(preset.id),
        process_names: preset.process_names,
        path_prefixes: Vec::new(),
        path_contains: preset.path_contains,
        mac_bundle_paths: preset.mac_bundle_paths,
        ignored_external_children: Vec::new(),
        include_children: preset.include_children,
        domains: Vec::new(),
        dst_cidrs: Vec::new(),
        dst_ports: Vec::new(),
        protocols: Vec::new(),
        target: clean_target,
    })
}

/// Evaluates installation and running-process status for all 7 built-in presets.
pub fn detect_preset_statuses(
    rules: &[AppProxyRule],
    tracker: &dyn ProcessTracker,
) -> Vec<AppPresetStatus> {
    let running = tracker.list_processes();
    let presets = list_app_presets();

    presets
        .into_iter()
        .map(|preset| {
            let matching_rule = rules
                .iter()
                .find(|r| r.preset_id.as_deref() == Some(preset.id.as_str()));

            let mut running_count = 0usize;
            let mut detected_paths: Vec<String> = Vec::new();

            for proc in &running {
                let name_hit = preset
                    .process_names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(&proc.name));
                let path_hit = proc.exe_path.as_deref().is_some_and(|p| {
                    let norm = p.replace('\\', "/").to_ascii_lowercase();
                    preset.path_contains.iter().any(|sub| {
                        !sub.is_empty()
                            && norm.contains(&sub.replace('\\', "/").to_ascii_lowercase())
                    }) || preset.mac_bundle_paths.iter().any(|b| {
                        !b.is_empty() && norm.starts_with(&b.to_ascii_lowercase())
                    })
                });
                if name_hit || path_hit {
                    running_count += 1;
                    if let Some(ref p) = proc.exe_path {
                        if !detected_paths.iter().any(|x| x.eq_ignore_ascii_case(p))
                            && detected_paths.len() < 4
                        {
                            detected_paths.push(p.clone());
                        }
                    }
                }
            }

            let disk_paths = probe_installed_preset_paths(&preset.id, &preset.mac_bundle_paths);
            for p in disk_paths {
                if !detected_paths.iter().any(|x| x.eq_ignore_ascii_case(&p))
                    && detected_paths.len() < 4
                {
                    detected_paths.push(p);
                }
            }

            let installed = running_count > 0 || !detected_paths.is_empty();

            AppPresetStatus {
                id: preset.id,
                name: preset.name,
                category: preset.category,
                description: preset.description,
                process_names: preset.process_names,
                path_contains: preset.path_contains,
                mac_bundle_paths: preset.mac_bundle_paths,
                include_children: preset.include_children,
                installed,
                running_count,
                detected_paths,
                enabled: matching_rule.map(|r| r.enabled).unwrap_or(false),
                rule_id: matching_rule.map(|r| r.id.clone()),
                target: matching_rule
                    .map(|r| r.target.clone())
                    .unwrap_or_else(|| "follow".to_string()),
            }
        })
        .collect()
}

fn probe_installed_preset_paths(preset_id: &str, mac_bundles: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    #[cfg(target_os = "macos")]
    {
        for bundle in mac_bundles {
            if Path::new(bundle).exists() {
                found.push(bundle.clone());
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            for bundle in mac_bundles {
                if let Some(name) = Path::new(bundle).file_name() {
                    let user_app = Path::new(&home).join("Applications").join(name);
                    if user_app.exists() {
                        found.push(user_app.to_string_lossy().to_string());
                    }
                }
            }
        }
        if preset_id == "git" && Path::new("/usr/bin/git").exists() {
            found.push("/usr/bin/git".to_string());
        }
    }

    #[cfg(target_os = "windows")]
    {
        let _ = mac_bundles;
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
        let pfx86 = std::env::var("ProgramFiles(x86)")
            .unwrap_or_else(|_| r"C:\Program Files (x86)".to_string());
        let appdata = std::env::var("APPDATA").unwrap_or_default();

        let candidates: Vec<String> = match preset_id {
            "antigravity" => vec![
                format!(r"{local}\Programs\Antigravity\Antigravity.exe"),
                format!(r"{local}\Antigravity\Antigravity.exe"),
                format!(r"{pf}\Antigravity\Antigravity.exe"),
            ],
            "cursor" => vec![
                format!(r"{local}\Programs\cursor\Cursor.exe"),
                format!(r"{pf}\cursor\Cursor.exe"),
            ],
            "vscode" => vec![
                format!(r"{local}\Programs\Microsoft VS Code\Code.exe"),
                format!(r"{pf}\Microsoft VS Code\Code.exe"),
            ],
            "git" => vec![
                format!(r"{pf}\Git\cmd\git.exe"),
                format!(r"{pf}\Git\bin\git.exe"),
            ],
            "discord" => vec![format!(r"{local}\Discord\Update.exe")],
            "telegram" => vec![
                format!(r"{appdata}\Telegram Desktop\Telegram.exe"),
                format!(r"{local}\Telegram Desktop\Telegram.exe"),
            ],
            "steam" => vec![
                format!(r"{pfx86}\Steam\steam.exe"),
                format!(r"{pf}\Steam\steam.exe"),
            ],
            _ => Vec::new(),
        };
        for c in candidates {
            if !c.is_empty() && Path::new(&c).exists() {
                found.push(c);
            }
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (preset_id, mac_bundles);
        if preset_id == "git" && Path::new("/usr/bin/git").exists() {
            found.push("/usr/bin/git".to_string());
        }
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_cross_platform_presets_exist_in_canonical_order() {
        let presets = list_app_presets();
        let ids: Vec<&str> = presets.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "antigravity",
                "cursor",
                "vscode",
                "git",
                "discord",
                "telegram",
                "steam"
            ]
        );
        let rule = preset_to_rule("cursor", "main", 20).unwrap();
        assert_eq!(rule.id, "preset-cursor");
        assert_eq!(rule.target, "main");
        assert!(rule
            .mac_bundle_paths
            .contains(&"/Applications/Cursor.app".to_string()));
    }
}
