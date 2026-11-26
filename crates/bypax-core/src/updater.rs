use crate::netguard::{OsNetworkAdapter, SystemNetworkAdapter};
use anyhow::{anyhow, bail, Context, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const GITHUB_REPO: &str = "Nexusyyan/bypax";
pub const LATEST_RELEASE_API_URL: &str =
    "https://api.github.com/repos/Nexusyyan/bypax/releases/latest";
pub const RELEASES_PAGE_URL: &str = "https://github.com/Nexusyyan/bypax/releases";
pub const ALLOWED_EXTERNAL_PREFIX: &str = "https://github.com/Nexusyyan/bypax";
pub const CURRENT_APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const APPLY_UPDATE_ARG: &str = "--apply-bypax-update";
pub const RESUME_AFTER_UPDATE_ARG: &str = "--resume-after-update";
pub const RESUME_CORE_ARG: &str = "--resume-core";
pub const RESUME_SYS_PROXY_ARG: &str = "--resume-sys-proxy";
pub const RESUME_APP_PROXY_ARG: &str = "--resume-app-proxy";
pub const RESUME_TUN_ARG: &str = "--resume-tun";
pub const CLEANUP_HELPER_ARG: &str = "--cleanup-helper";
pub const BYPAX_SERVICE_NAME: &str = "BypaxService";

const MAX_RELEASE_NOTES_CHARS: usize = 4000;
const MAX_ZIP_ENTRIES: usize = 512;
const MAX_ZIP_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;
const MIN_PE_BYTES: u64 = 64 * 1024;
const MIN_DRIVER_PE_BYTES: u64 = 8 * 1024;
const PROGRESS_EMIT_INTERVAL_MS: u64 = 100;
const DEFAULT_SWAP_MAX_ATTEMPTS: usize = 25;
const DEFAULT_SWAP_RETRY_DELAY_MS: u64 = 200;

const PORTABLE_WINDIVERT_FILES: &[(&str, bool)] = &[
    ("runtime/windivert/WinDivert.dll", true),
    ("runtime/windivert/WinDivert64.sys", true),
    ("runtime/windivert/WINDIVERT_LICENSE.txt", false),
    ("runtime/windivert/WINDIVERT_README.txt", false),
];

const PORTABLE_SKILL_REL_PATH: &str = "skills/bypax-agent/SKILL.md";

const PORTABLE_DOC_FILES: &[&str] = &[
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "README.md",
    "README.zh-CN.md",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyChannel {
    LocalBypax(u16),
    SystemProxy(String),
    Direct,
}

impl ProxyChannel {
    pub fn label(&self) -> &'static str {
        match self {
            ProxyChannel::LocalBypax(_) => "proxy:bypax",
            ProxyChannel::SystemProxy(_) => "proxy:system",
            ProxyChannel::Direct => "direct",
        }
    }

    pub fn build_client(
        &self,
        connect_timeout_secs: u64,
        timeout_secs: u64,
    ) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .user_agent(format!("Bypax/{}", CURRENT_APP_VERSION))
            .connect_timeout(Duration::from_secs(connect_timeout_secs))
            .timeout(Duration::from_secs(timeout_secs));
        match self {
            ProxyChannel::LocalBypax(port) => {
                builder =
                    builder.proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", port))?);
            }
            ProxyChannel::SystemProxy(url) => {
                builder = builder.proxy(reqwest::Proxy::all(url)?);
            }
            ProxyChannel::Direct => {
                builder = builder.no_proxy();
            }
        }
        Ok(builder.build()?)
    }
}

/// Normalizes a Windows `ProxyServer` string or environment proxy value into a URL accepted by reqwest.
pub fn normalize_proxy_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("://") {
        return Some(trimmed.to_string());
    }
    if trimmed.contains('=') {
        let mut https_val: Option<&str> = None;
        let mut http_val: Option<&str> = None;
        let mut socks_val: Option<&str> = None;
        for part in trimmed.split(';') {
            let Some((k, v)) = part.split_once('=') else {
                continue;
            };
            let v = v.trim();
            if v.is_empty() {
                continue;
            }
            match k.trim().to_ascii_lowercase().as_str() {
                "https" => https_val = Some(v),
                "http" => http_val = Some(v),
                "socks" | "socks5" => socks_val = Some(v),
                _ => {}
            }
        }
        if let Some(v) = https_val.or(http_val) {
            return Some(if v.contains("://") {
                v.to_string()
            } else {
                format!("http://{}", v)
            });
        }
        if let Some(v) = socks_val {
            return Some(if v.contains("://") {
                v.to_string()
            } else {
                format!("socks5://{}", v)
            });
        }
        return None;
    }
    Some(format!("http://{}", trimmed))
}

/// Detects an enabled OS or environment proxy URL (excluding the caller's own local port if given).
pub fn detect_system_proxy_url(exclude_local_port: Option<u16>) -> Option<String> {
    let candidate = OsNetworkAdapter
        .capture_snapshot()
        .ok()
        .filter(|s| s.proxy_enable)
        .and_then(|s| normalize_proxy_url(&s.proxy_server))
        .or_else(|| {
            for key in [
                "HTTPS_PROXY",
                "https_proxy",
                "ALL_PROXY",
                "all_proxy",
                "HTTP_PROXY",
                "http_proxy",
            ] {
                if let Ok(val) = std::env::var(key) {
                    if let Some(url) = normalize_proxy_url(&val) {
                        return Some(url);
                    }
                }
            }
            None
        })?;

    if let Some(port) = exclude_local_port {
        let self_http = format!("http://127.0.0.1:{}", port);
        let self_localhost = format!("http://localhost:{}", port);
        if candidate.eq_ignore_ascii_case(&self_http)
            || candidate.eq_ignore_ascii_case(&self_localhost)
        {
            return None;
        }
    }
    Some(candidate)
}

/// Builds ordered outbound channels: Bypax active proxy -> OS system proxy -> Direct.
pub fn build_proxy_channels(local_proxy_port: Option<u16>) -> Vec<ProxyChannel> {
    let mut channels = Vec::with_capacity(3);
    if let Some(port) = local_proxy_port {
        channels.push(ProxyChannel::LocalBypax(port));
    }
    if let Some(sys) = detect_system_proxy_url(local_proxy_port) {
        channels.push(ProxyChannel::SystemProxy(sys));
    }
    channels.push(ProxyChannel::Direct);
    channels
}

/// Fetches a text payload across Bypax proxy -> OS system proxy -> direct fallback.
pub async fn fetch_text_via_channels(
    url: &str,
    local_proxy_port: Option<u16>,
    user_agent: Option<&str>,
    accept: Option<&str>,
    timeout_secs: u64,
) -> Result<(String, String)> {
    let channels = build_proxy_channels(local_proxy_port);
    let mut last_err = String::new();
    for ch in &channels {
        let client = match ch.build_client(8, timeout_secs) {
            Ok(c) => c,
            Err(e) => {
                last_err = format!("{}: {}", ch.label(), e);
                continue;
            }
        };
        let mut req = client.get(url);
        if let Some(ua) = user_agent {
            req = req.header(reqwest::header::USER_AGENT, ua);
        }
        if let Some(acc) = accept {
            req = req.header(reqwest::header::ACCEPT, acc);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(text) => return Ok((text, ch.label().to_string())),
                Err(e) => last_err = format!("{}: {}", ch.label(), e),
            },
            Ok(resp) => {
                last_err = format!("{}: HTTP {}", ch.label(), resp.status().as_u16());
            }
            Err(e) => {
                last_err = format!("{}: {}", ch.label(), e);
            }
        }
    }
    Err(anyhow!("Failed to fetch {} ({})", url, last_err))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedFileSwap {
    pub staged_path: PathBuf,
    pub relative_target: PathBuf,
    #[serde(default)]
    pub requires_service_stop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateCheckReport {
    pub current_version: String,
    pub latest_version: String,
    pub latest_tag: String,
    pub update_available: bool,
    pub no_release_yet: bool,
    pub release_name: String,
    pub release_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_asset_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_asset_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_asset_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_asset_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksums_url: Option<String>,
    pub install_mode: String,
    pub in_app_update_supported: bool,
    pub checked_via: String,
    pub checked_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppUpdateStage {
    Idle,
    Checking,
    Downloading,
    Verifying,
    Extracting,
    ReadyToRestart,
    Restarting,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateState {
    pub stage: AppUpdateStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_kind: Option<String>,
    pub downloaded_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_exe_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_core_exe_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_cli_exe_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_service_exe_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub staged_extra_files: Vec<StagedFileSwap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for AppUpdateState {
    fn default() -> Self {
        Self {
            stage: AppUpdateStage::Idle,
            target_version: None,
            target_tag: None,
            asset_name: None,
            asset_kind: None,
            downloaded_bytes: 0,
            total_bytes: None,
            percent: None,
            via: None,
            staged_dir: None,
            staged_exe_path: None,
            staged_core_exe_path: None,
            staged_cli_exe_path: None,
            staged_service_exe_path: None,
            staged_extra_files: Vec::new(),
            sha256: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlan {
    pub parent_pid: u32,
    pub target_exe: PathBuf,
    pub target_dir: PathBuf,
    pub portable_mode: bool,
    pub staged_dir: PathBuf,
    pub staged_exe: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_core_exe: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_cli_exe: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_service_exe: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_swaps: Vec<StagedFileSwap>,
    #[serde(default)]
    pub docs_to_copy: Vec<String>,
    pub resume_core: bool,
    pub resume_sys_proxy: bool,
    #[serde(default)]
    pub resume_app_proxy: bool,
    #[serde(default)]
    pub resume_tun: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    pub from_version: String,
    pub to_version: String,
    pub to_tag: String,
    pub result_file: PathBuf,
}

impl UpdatePlan {
    /// Builds a complete multi-binary `UpdatePlan` from a staged `AppUpdateState`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_staged(
        staged: &AppUpdateState,
        parent_pid: u32,
        target_exe: PathBuf,
        target_dir: PathBuf,
        portable_mode: bool,
        staged_dir: PathBuf,
        staged_exe: PathBuf,
        resume_core: bool,
        resume_sys_proxy: bool,
        resume_app_proxy: bool,
        resume_tun: bool,
        result_file: PathBuf,
    ) -> Self {
        Self {
            parent_pid,
            target_exe,
            target_dir,
            portable_mode,
            staged_dir,
            staged_exe,
            staged_core_exe: staged.staged_core_exe_path.as_ref().map(PathBuf::from),
            staged_cli_exe: staged.staged_cli_exe_path.as_ref().map(PathBuf::from),
            staged_service_exe: staged.staged_service_exe_path.as_ref().map(PathBuf::from),
            extra_swaps: staged.staged_extra_files.clone(),
            docs_to_copy: PORTABLE_DOC_FILES.iter().map(|s| s.to_string()).collect(),
            resume_core,
            resume_sys_proxy,
            resume_app_proxy,
            resume_tun,
            service_name: Some(BYPAX_SERVICE_NAME.to_string()),
            from_version: CURRENT_APP_VERSION.to_string(),
            to_version: staged
                .target_version
                .clone()
                .unwrap_or_else(|| CURRENT_APP_VERSION.to_string()),
            to_tag: staged
                .target_tag
                .clone()
                .unwrap_or_else(|| format!("v{}", CURRENT_APP_VERSION)),
            result_file,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateApplyResult {
    pub success: bool,
    pub from_version: String,
    pub to_version: String,
    pub to_tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub applied_at: String,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseResponse {
    tag_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    assets: Vec<GithubReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

pub fn is_safe_release_url(url: &str) -> bool {
    let trimmed = url.trim();
    trimmed == ALLOWED_EXTERNAL_PREFIX
        || trimmed.starts_with(&format!("{}/", ALLOWED_EXTERNAL_PREFIX))
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedSemver {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<String>,
}

fn parse_semver(raw: &str) -> Option<ParsedSemver> {
    let clean = raw.trim().trim_start_matches(['v', 'V']);
    let clean = clean.split('+').next().unwrap_or(clean);
    let (core, pre) = match clean.split_once('-') {
        Some((c, p)) => (c, Some(p.to_string())),
        None => (clean, None),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    Some(ParsedSemver {
        major,
        minor,
        patch,
        prerelease: pre.filter(|s| !s.is_empty()),
    })
}

/// Compares two SemVer strings (`v0.2.0` vs `0.1.0`, stable > prerelease).
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    match (parse_semver(a), parse_semver(b)) {
        (Some(pa), Some(pb)) => (pa.major, pa.minor, pa.patch)
            .cmp(&(pb.major, pb.minor, pb.patch))
            .then_with(|| match (&pa.prerelease, &pb.prerelease) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(la), Some(lb)) => la.cmp(lb),
            }),
        _ => a.trim_start_matches('v').cmp(b.trim_start_matches('v')),
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push_str("\n...");
    out
}

/// Parses a `SHA256SUMS.txt` file and returns the lowercase 64-hex digest for `asset_name`.
pub fn parse_sha256sums(content: &str, asset_name: &str) -> Option<String> {
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let file = parts.next()?;
        let clean_file = file
            .trim_start_matches('*')
            .trim_start_matches("./")
            .trim_start_matches(".\\");
        if clean_file.eq_ignore_ascii_case(asset_name)
            && hash.len() == 64
            && hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

/// Validates that a file is a plausible Windows PE image (`MZ` header + `PE\0\0` signature)
/// with at least `min_bytes` size.
pub fn validate_pe_image(path: &Path, min_bytes: u64) -> Result<()> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("Missing executable at {}", path.display()))?;
    if meta.len() < min_bytes {
        bail!(
            "PE image too small ({} bytes; expected >= {} bytes)",
            meta.len(),
            min_bytes
        );
    }
    let mut f = std::fs::File::open(path)?;
    let mut dos_hdr = [0u8; 64];
    f.read_exact(&mut dos_hdr)?;
    if &dos_hdr[0..2] != b"MZ" {
        bail!("Invalid PE header: missing MZ magic");
    }
    let e_lfanew = u32::from_le_bytes([dos_hdr[60], dos_hdr[61], dos_hdr[62], dos_hdr[63]]) as u64;
    if e_lfanew < 64 || e_lfanew + 4 > meta.len() {
        bail!("Invalid PE header: corrupted e_lfanew offset");
    }
    use std::io::{Seek, SeekFrom};
    f.seek(SeekFrom::Start(e_lfanew))?;
    let mut sig = [0u8; 4];
    f.read_exact(&mut sig)?;
    if &sig != b"PE\0\0" {
        bail!("Invalid PE header: missing PE signature");
    }
    Ok(())
}

/// Validates that a file is a plausible Windows PE executable (`MZ` header + `PE\0\0` signature).
pub fn validate_pe_header(path: &Path) -> Result<()> {
    validate_pe_image(path, MIN_PE_BYTES)
}

/// Detects whether companion binaries (`bypax-cli.exe`, `bypax-service.exe`, or `runtime/windivert`)
/// are installed alongside the main executable, indicating a multi-binary bundle layout.
pub fn has_companion_binaries_in(dir: &Path) -> bool {
    dir.join("bypax-cli.exe").is_file()
        || dir.join("bypax-service.exe").is_file()
        || dir.join("runtime").join("windivert").is_dir()
}

/// Parses GitHub Releases API JSON into a verified `AppUpdateCheckReport`.
///
/// Selection strategy:
/// - Portable mode or multi-binary bundle installs always prefer `portable_zip` so
///   `bypax.exe`, `bypax-cli.exe`, `bypax-service.exe`, core, drivers, and agent skills
///   upgrade together cleanly.
/// - Pure single-file standalone installs (no portable marker and no companion binaries)
///   prefer the lightweight `standalone_exe`.
pub fn parse_app_release_json_with_layout(
    current_version: &str,
    json_body: &str,
    via: &str,
    portable_mode: bool,
    has_companion_binaries: bool,
) -> Result<AppUpdateCheckReport> {
    let parsed: GithubReleaseResponse =
        serde_json::from_str(json_body).context("Invalid GitHub release JSON")?;
    let latest_tag = parsed.tag_name.trim().to_string();
    if latest_tag.is_empty() {
        bail!("GitHub release missing tag_name");
    }
    let latest_version = latest_tag.trim_start_matches(['v', 'V']).to_string();
    let update_available = compare_versions(&latest_version, current_version) == Ordering::Greater;

    let release_url = parsed
        .html_url
        .filter(|u| is_safe_release_url(u))
        .unwrap_or_else(|| RELEASES_PAGE_URL.to_string());

    let mut portable_zip: Option<(String, String, u64)> = None;
    let mut nodriver_zip: Option<(String, String, u64)> = None;
    let mut fallback_zip: Option<(String, String, u64)> = None;
    let mut standalone_exe: Option<(String, String, u64)> = None;
    let mut checksums_url: Option<String> = None;

    for asset in parsed.assets {
        if !is_safe_release_url(&asset.browser_download_url) {
            continue;
        }
        let lower = asset.name.to_ascii_lowercase();
        if lower == "sha256sums.txt" {
            checksums_url = Some(asset.browser_download_url);
        } else if lower.ends_with("-windows-portable.zip") {
            portable_zip = Some((asset.name, asset.browser_download_url, asset.size));
        } else if lower.ends_with("-windows-nodriver.zip") {
            nodriver_zip = Some((asset.name, asset.browser_download_url, asset.size));
        } else if lower.contains("windows") && lower.ends_with(".zip") {
            fallback_zip = Some((asset.name, asset.browser_download_url, asset.size));
        } else if lower.ends_with("-windows.exe")
            || (lower.contains("windows") && lower.ends_with(".exe"))
        {
            standalone_exe = Some((asset.name, asset.browser_download_url, asset.size));
        }
    }

    let preferred_zip = portable_zip.or(fallback_zip).or(nodriver_zip);
    let prefer_bundle = portable_mode || has_companion_binaries;

    let (selected_asset_kind, selected) = if prefer_bundle {
        if let Some(z) = preferred_zip {
            (Some("portable_zip".to_string()), Some(z))
        } else if let Some(e) = standalone_exe {
            (Some("standalone_exe".to_string()), Some(e))
        } else {
            (None, None)
        }
    } else if let Some(e) = standalone_exe {
        (Some("standalone_exe".to_string()), Some(e))
    } else if let Some(z) = preferred_zip {
        (Some("portable_zip".to_string()), Some(z))
    } else {
        (None, None)
    };

    let (selected_asset_name, selected_asset_url, selected_asset_size) = match selected {
        Some((n, u, s)) => (Some(n), Some(u), if s > 0 { Some(s) } else { None }),
        None => (None, None, None),
    };

    let in_app_update_supported = cfg!(target_os = "windows")
        && selected_asset_url.is_some()
        && checksums_url.is_some();

    let release_notes = parsed
        .body
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty())
        .map(|b| truncate_chars(&b, MAX_RELEASE_NOTES_CHARS));

    Ok(AppUpdateCheckReport {
        current_version: current_version.to_string(),
        latest_version,
        latest_tag: latest_tag.clone(),
        update_available,
        no_release_yet: false,
        release_name: parsed
            .name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(latest_tag),
        release_url,
        published_at: parsed.published_at.filter(|s| !s.trim().is_empty()),
        release_notes,
        selected_asset_name,
        selected_asset_url,
        selected_asset_size,
        selected_asset_kind,
        checksums_url,
        install_mode: if portable_mode {
            "portable".to_string()
        } else {
            "standalone".to_string()
        },
        in_app_update_supported,
        checked_via: via.to_string(),
        checked_at_ms: now_epoch_ms(),
    })
}

/// Parses GitHub Releases API JSON into a verified `AppUpdateCheckReport`.
pub fn parse_app_release_json(
    current_version: &str,
    json_body: &str,
    via: &str,
    portable_mode: bool,
    _core_installed: bool,
) -> Result<AppUpdateCheckReport> {
    parse_app_release_json_with_layout(current_version, json_body, via, portable_mode, false)
}

/// Checks GitHub Releases for a newer Bypax version via active proxy -> system proxy -> direct.
pub async fn check_for_app_update(
    local_proxy_port: Option<u16>,
    portable_mode: bool,
    _core_installed: bool,
) -> Result<AppUpdateCheckReport> {
    let has_companions = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(has_companion_binaries_in))
        .unwrap_or(false);
    let channels = build_proxy_channels(local_proxy_port);
    let mut last_err = String::new();

    for ch in &channels {
        let client = match ch.build_client(8, 15) {
            Ok(c) => c,
            Err(e) => {
                last_err = format!("{}: {}", ch.label(), e);
                continue;
            }
        };
        let resp = match client
            .get(LATEST_RELEASE_API_URL)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_err = format!("{}: {}", ch.label(), e);
                continue;
            }
        };

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(AppUpdateCheckReport {
                current_version: CURRENT_APP_VERSION.to_string(),
                latest_version: CURRENT_APP_VERSION.to_string(),
                latest_tag: format!("v{}", CURRENT_APP_VERSION),
                update_available: false,
                no_release_yet: true,
                release_name: format!("Bypax v{}", CURRENT_APP_VERSION),
                release_url: RELEASES_PAGE_URL.to_string(),
                published_at: None,
                release_notes: None,
                selected_asset_name: None,
                selected_asset_url: None,
                selected_asset_size: None,
                selected_asset_kind: None,
                checksums_url: None,
                install_mode: if portable_mode {
                    "portable".to_string()
                } else {
                    "standalone".to_string()
                },
                in_app_update_supported: false,
                checked_via: ch.label().to_string(),
                checked_at_ms: now_epoch_ms(),
            });
        }

        if !resp.status().is_success() {
            last_err = format!("{}: HTTP {}", ch.label(), resp.status().as_u16());
            continue;
        }

        let body = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                last_err = format!("{}: {}", ch.label(), e);
                continue;
            }
        };

        return parse_app_release_json_with_layout(
            CURRENT_APP_VERSION,
            &body,
            ch.label(),
            portable_mode,
            has_companions,
        );
    }

    Err(anyhow!("Unable to check GitHub Releases ({})", last_err))
}

fn is_protected_user_data_path(rel: &Path) -> bool {
    for comp in rel.components() {
        if let Component::Normal(os) = comp {
            if let Some(seg) = os.to_str() {
                if seg.eq_ignore_ascii_case("bypax-data")
                    || seg.eq_ignore_ascii_case("portable.json")
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Safely extracts a release ZIP archive with anti-Zip-Slip checks, size caps, and user-data protection.
pub fn extract_zip_safely(zip_path: &Path, dest_dir: &Path) -> Result<()> {
    let file = std::fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file).context("Invalid ZIP archive")?;
    if archive.len() > MAX_ZIP_ENTRIES {
        bail!(
            "ZIP archive exceeds maximum entry count ({})",
            MAX_ZIP_ENTRIES
        );
    }

    std::fs::create_dir_all(dest_dir)?;
    let mut total_bytes: u64 = 0;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.is_symlink() {
            bail!("Refusing symlink inside update archive: {}", entry.name());
        }
        let rel = entry
            .enclosed_name()
            .ok_or_else(|| anyhow!("Unsafe path traversal entry in ZIP: {}", entry.name()))?
            .to_path_buf();

        // Guard against any nested path escaping or touching user data / portable marker.
        for comp in rel.components() {
            if matches!(
                comp,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            ) {
                bail!("Unsafe component in ZIP entry: {}", entry.name());
            }
        }
        if is_protected_user_data_path(&rel) {
            continue;
        }

        let out_path = dest_dir.join(&rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut out_file = std::fs::File::create(&out_path)?;
        let mut buf = [0u8; 65536];
        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total_bytes = total_bytes.saturating_add(n as u64);
            if total_bytes > MAX_ZIP_UNPACKED_BYTES {
                bail!("ZIP archive exceeds maximum allowed unpacked size");
            }
            use std::io::Write;
            out_file.write_all(&buf[..n])?;
        }
    }

    Ok(())
}

fn find_file_in_staged(root: &Path, rel_path: &str) -> Option<PathBuf> {
    let rel = PathBuf::from(rel_path);
    let direct = root.join(&rel);
    if direct.is_file() {
        return Some(direct);
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let nested = p.join(&rel);
                if nested.is_file() {
                    return Some(nested);
                }
            }
        }
    }
    None
}

/// Discovered companion binaries and bundle files in a staged portable update payload.
#[derive(Debug, Clone, Default)]
pub struct DiscoveredBundle {
    pub cli_exe: Option<PathBuf>,
    pub service_exe: Option<PathBuf>,
    pub core_exe: Option<PathBuf>,
    pub extra_swaps: Vec<StagedFileSwap>,
}

/// Discovers and validates all multi-binary portable assets relative to `payload_root`
/// (the directory containing the staged `bypax.exe`).
pub fn discover_staged_bundle_files(
    payload_root: &Path,
    validate_pe: bool,
) -> Result<DiscoveredBundle> {
    let mut bundle = DiscoveredBundle::default();

    let cli_path = payload_root.join("bypax-cli.exe");
    if cli_path.is_file() {
        if validate_pe {
            validate_pe_header(&cli_path)
                .context("Invalid PE header for staged bypax-cli.exe")?;
        }
        bundle.cli_exe = Some(cli_path.clone());
        bundle.extra_swaps.push(StagedFileSwap {
            staged_path: cli_path,
            relative_target: PathBuf::from("bypax-cli.exe"),
            requires_service_stop: false,
        });
    }

    let svc_path = payload_root.join("bypax-service.exe");
    if svc_path.is_file() {
        if validate_pe {
            validate_pe_header(&svc_path)
                .context("Invalid PE header for staged bypax-service.exe")?;
        }
        bundle.service_exe = Some(svc_path.clone());
        bundle.extra_swaps.push(StagedFileSwap {
            staged_path: svc_path,
            relative_target: PathBuf::from("bypax-service.exe"),
            requires_service_stop: true,
        });
    }

    let core_path = payload_root.join("core").join("sing-box.exe");
    if core_path.is_file() {
        if validate_pe {
            validate_pe_header(&core_path)
                .context("Invalid PE header for staged core/sing-box.exe")?;
        }
        bundle.core_exe = Some(core_path.clone());
        bundle.extra_swaps.push(StagedFileSwap {
            staged_path: core_path,
            relative_target: PathBuf::from("core").join("sing-box.exe"),
            requires_service_stop: true,
        });
    }

    for (rel, is_pe_driver) in PORTABLE_WINDIVERT_FILES {
        let path = payload_root.join(rel);
        if path.is_file() {
            if validate_pe && *is_pe_driver {
                validate_pe_image(&path, MIN_DRIVER_PE_BYTES)
                    .with_context(|| format!("Invalid PE image for staged {}", rel))?;
            }
            bundle.extra_swaps.push(StagedFileSwap {
                staged_path: path,
                relative_target: PathBuf::from(rel),
                requires_service_stop: true,
            });
        }
    }

    let skill_path = payload_root.join(PORTABLE_SKILL_REL_PATH);
    if skill_path.is_file() {
        bundle.extra_swaps.push(StagedFileSwap {
            staged_path: skill_path,
            relative_target: PathBuf::from(PORTABLE_SKILL_REL_PATH),
            requires_service_stop: false,
        });
    }

    Ok(bundle)
}

/// Downloads, cryptographically verifies (mandatory SHA256SUMS.txt), and stages an app update.
pub async fn download_and_stage_update<F>(
    report: &AppUpdateCheckReport,
    updates_root: &Path,
    local_proxy_port: Option<u16>,
    cancel: Arc<AtomicBool>,
    on_progress: F,
) -> Result<AppUpdateState>
where
    F: Fn(AppUpdateState) + Send + Sync,
{
    let asset_name = report
        .selected_asset_name
        .as_deref()
        .ok_or_else(|| anyhow!("No downloadable release asset found for this platform"))?;
    let asset_url = report
        .selected_asset_url
        .as_deref()
        .filter(|u| is_safe_release_url(u))
        .ok_or_else(|| anyhow!("Release asset URL missing or untrusted"))?;
    let asset_kind = report
        .selected_asset_kind
        .as_deref()
        .unwrap_or("standalone_exe");
    let checksums_url = report
        .checksums_url
        .as_deref()
        .filter(|u| is_safe_release_url(u))
        .ok_or_else(|| {
            anyhow!("SHA256SUMS.txt is missing from this release; refusing unverified update")
        })?;

    let mut state = AppUpdateState {
        stage: AppUpdateStage::Downloading,
        target_version: Some(report.latest_version.clone()),
        target_tag: Some(report.latest_tag.clone()),
        asset_name: Some(asset_name.to_string()),
        asset_kind: Some(asset_kind.to_string()),
        downloaded_bytes: 0,
        total_bytes: report.selected_asset_size,
        percent: Some(0),
        via: None,
        staged_dir: None,
        staged_exe_path: None,
        staged_core_exe_path: None,
        staged_cli_exe_path: None,
        staged_service_exe_path: None,
        staged_extra_files: Vec::new(),
        sha256: None,
        error: None,
    };
    on_progress(state.clone());

    if cancel.load(AtomicOrdering::Relaxed) {
        bail!("UPDATE_CANCELLED");
    }

    // 1. Fetch official SHA256SUMS.txt strictly from GitHub (never third-party mirrors).
    let (sums_text, _sums_via) =
        fetch_text_via_channels(checksums_url, local_proxy_port, None, None, 20)
            .await
            .context("Failed to fetch official SHA256SUMS.txt")?;

    let expected_sha256 = parse_sha256sums(&sums_text, asset_name).ok_or_else(|| {
        anyhow!(
            "No valid SHA-256 entry found for {} in SHA256SUMS.txt",
            asset_name
        )
    })?;

    // 2. Prepare clean staging directory.
    std::fs::create_dir_all(updates_root)?;
    let stage_id = format!(
        "stage-{}-{}",
        sanitize_version_dir(&report.latest_tag),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let stage_dir = updates_root.join(&stage_id);
    std::fs::create_dir_all(&stage_dir)?;
    let part_path = stage_dir.join("download.part");

    // 3. Build candidate (url, channel, label) download routes:
    //    official GitHub via proxy/system/direct first, then SHA-256-verified mirrors.
    let mut attempts: Vec<(String, ProxyChannel, String)> = Vec::new();
    for ch in build_proxy_channels(local_proxy_port) {
        attempts.push((asset_url.to_string(), ch.clone(), ch.label().to_string()));
    }
    attempts.push((
        format!("https://ghfast.top/{}", asset_url),
        ProxyChannel::Direct,
        "mirror:ghfast".to_string(),
    ));
    attempts.push((
        format!("https://gh-proxy.com/{}", asset_url),
        ProxyChannel::Direct,
        "mirror:gh-proxy".to_string(),
    ));

    let mut verified_via: Option<String> = None;
    let mut last_err = String::new();

    for (url, ch, via_label) in &attempts {
        if cancel.load(AtomicOrdering::Relaxed) {
            let _ = std::fs::remove_dir_all(&stage_dir);
            bail!("UPDATE_CANCELLED");
        }
        let _ = std::fs::remove_file(&part_path);

        let client = match ch.build_client(10, 300) {
            Ok(c) => c,
            Err(e) => {
                last_err = format!("{}: {}", via_label, e);
                continue;
            }
        };

        let resp = match client.get(url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                last_err = format!("{}: HTTP {}", via_label, r.status().as_u16());
                continue;
            }
            Err(e) => {
                last_err = format!("{}: {}", via_label, e);
                continue;
            }
        };

        let content_len = resp.content_length().or(report.selected_asset_size);
        state.via = Some(via_label.clone());
        state.total_bytes = content_len;
        state.downloaded_bytes = 0;
        state.percent = Some(0);
        on_progress(state.clone());

        let mut file = match tokio::fs::File::create(&part_path).await {
            Ok(f) => f,
            Err(e) => {
                last_err = format!("create file: {}", e);
                continue;
            }
        };

        let mut hasher = Sha256::new();
        let mut downloaded: u64 = 0;
        let mut last_emit = Instant::now();
        let mut stream = resp.bytes_stream();
        let mut stream_ok = true;

        use tokio::io::AsyncWriteExt;
        while let Some(chunk_res) = stream.next().await {
            if cancel.load(AtomicOrdering::Relaxed) {
                drop(file);
                let _ = std::fs::remove_dir_all(&stage_dir);
                bail!("UPDATE_CANCELLED");
            }
            match chunk_res {
                Ok(chunk) => {
                    hasher.update(&chunk);
                    if let Err(e) = file.write_all(&chunk).await {
                        last_err = format!("write chunk: {}", e);
                        stream_ok = false;
                        break;
                    }
                    downloaded = downloaded.saturating_add(chunk.len() as u64);
                    if last_emit.elapsed() >= Duration::from_millis(PROGRESS_EMIT_INTERVAL_MS) {
                        state.downloaded_bytes = downloaded;
                        state.percent = content_len
                            .filter(|t| *t > 0)
                            .map(|t| ((downloaded.saturating_mul(100)) / t).min(99) as u8);
                        on_progress(state.clone());
                        last_emit = Instant::now();
                    }
                }
                Err(e) => {
                    last_err = format!("{}: {}", via_label, e);
                    stream_ok = false;
                    break;
                }
            }
        }

        if !stream_ok {
            drop(file);
            let _ = std::fs::remove_file(&part_path);
            continue;
        }
        if let Err(e) = file.flush().await {
            last_err = format!("flush: {}", e);
            drop(file);
            let _ = std::fs::remove_file(&part_path);
            continue;
        }
        drop(file);

        // Mandatory cryptographic SHA-256 verification.
        state.stage = AppUpdateStage::Verifying;
        state.downloaded_bytes = downloaded;
        state.total_bytes = Some(downloaded);
        state.percent = Some(100);
        on_progress(state.clone());

        let got_sha = hex::encode(hasher.finalize());
        if !got_sha.eq_ignore_ascii_case(&expected_sha256) {
            last_err = format!(
                "SHA-256 mismatch from {} (expected {}, got {})",
                via_label, expected_sha256, got_sha
            );
            let _ = std::fs::remove_file(&part_path);
            state.stage = AppUpdateStage::Downloading;
            continue;
        }

        verified_via = Some(via_label.clone());
        break;
    }

    let Some(final_via) = verified_via else {
        let _ = std::fs::remove_dir_all(&stage_dir);
        bail!("Unable to download and verify update ({})", last_err);
    };

    // 4. Stage & validate executable payload(s).
    let payload_dir = stage_dir.join("payload");
    std::fs::create_dir_all(&payload_dir)?;

    let (staged_exe, staged_cli_exe, staged_service_exe, staged_core_exe, staged_extra_files) =
        if asset_kind == "portable_zip" {
            state.stage = AppUpdateStage::Extracting;
            on_progress(state.clone());
            if let Err(e) = extract_zip_safely(&part_path, &payload_dir) {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
            let _ = std::fs::remove_file(&part_path);

            let exe = find_file_in_staged(&payload_dir, "bypax.exe").ok_or_else(|| {
                let _ = std::fs::remove_dir_all(&stage_dir);
                anyhow!("bypax.exe not found inside update ZIP archive")
            })?;
            if let Err(e) = validate_pe_header(&exe) {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
            let payload_root = exe.parent().unwrap_or(&payload_dir);
            let bundle = match discover_staged_bundle_files(payload_root, true) {
                Ok(b) => b,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&stage_dir);
                    return Err(e);
                }
            };
            (
                exe,
                bundle.cli_exe,
                bundle.service_exe,
                bundle.core_exe,
                bundle.extra_swaps,
            )
        } else {
            if let Err(e) = validate_pe_header(&part_path) {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
            let exe = payload_dir.join("bypax.exe");
            std::fs::rename(&part_path, &exe)?;
            (exe, None, None, None, Vec::new())
        };

    state.stage = AppUpdateStage::ReadyToRestart;
    state.via = Some(final_via);
    state.staged_dir = Some(stage_dir.to_string_lossy().to_string());
    state.staged_exe_path = Some(staged_exe.to_string_lossy().to_string());
    state.staged_core_exe_path = staged_core_exe.map(|p| p.to_string_lossy().to_string());
    state.staged_cli_exe_path = staged_cli_exe.map(|p| p.to_string_lossy().to_string());
    state.staged_service_exe_path = staged_service_exe.map(|p| p.to_string_lossy().to_string());
    state.staged_extra_files = staged_extra_files;
    state.sha256 = Some(expected_sha256);
    state.percent = Some(100);
    state.error = None;
    on_progress(state.clone());

    Ok(state)
}

fn sanitize_version_dir(tag: &str) -> String {
    tag.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Checks whether the target installation directory is writable before exiting for self-update.
pub fn ensure_target_dir_writable(target_dir: &Path) -> Result<()> {
    let probe = target_dir.join(format!(
        ".bypax-write-probe-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::write(&probe, b"ok").with_context(|| {
        format!(
            "Installation folder {} is not writable; move Bypax to a writable directory or run as administrator",
            target_dir.display()
        )
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Copies the current executable into a detached helper binary and launches it to apply `plan`
/// after this process exits.
pub fn spawn_detached_update_helper(plan: &UpdatePlan) -> Result<()> {
    if !plan.staged_exe.is_file() {
        bail!("Staged update binary missing: {}", plan.staged_exe.display());
    }
    ensure_target_dir_writable(&plan.target_dir)?;

    let current_exe = std::env::current_exe().context("Cannot resolve current executable")?;
    let temp_dir = std::env::temp_dir();
    let nonce = &uuid::Uuid::new_v4().simple().to_string()[..10];
    let helper_exe = temp_dir.join(format!("bypax-updater-{}.exe", nonce));
    let plan_path = temp_dir.join(format!("bypax-update-plan-{}.json", nonce));

    std::fs::copy(&current_exe, &helper_exe).context("Failed to copy updater helper binary")?;
    std::fs::write(&plan_path, serde_json::to_string_pretty(plan)?)
        .context("Failed to persist update plan")?;

    let mut cmd = std::process::Command::new(&helper_exe);
    cmd.arg(APPLY_UPDATE_ARG)
        .arg(&plan_path)
        .current_dir(&temp_dir);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    cmd.spawn()
        .context("Failed to launch detached updater helper")?;
    Ok(())
}

/// Intercepts helper invocation in `main()` before Tauri or single-instance locks initialize.
pub fn maybe_run_updater_helper(args: &[String]) -> Option<i32> {
    let idx = args.iter().position(|a| a == APPLY_UPDATE_ARG)?;
    let Some(plan_arg) = args.get(idx + 1) else {
        return Some(2);
    };
    let plan_path = PathBuf::from(plan_arg);
    match apply_update_plan(&plan_path) {
        Ok(()) => Some(0),
        Err(_) => Some(1),
    }
}

/// Computes the sibling `.prev` backup path for a target file.
pub fn backup_path_for(target: &Path) -> PathBuf {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bypax.exe");
    if let Some(stem) = target.file_stem().and_then(|s| s.to_str()) {
        if let Some(ext) = target.extension().and_then(|s| s.to_str()) {
            parent.join(format!("{}.prev.{}", stem, ext))
        } else {
            parent.join(format!("{}.prev", stem))
        }
    } else {
        parent.join(format!("{}.prev", file_name))
    }
}

fn sibling_tmp_path_for(target: &Path) -> PathBuf {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bypax.exe");
    parent.join(format!(".{}.new.tmp", file_name))
}

#[derive(Debug, Clone)]
struct CompletedSwap {
    target: PathBuf,
    backup: PathBuf,
    existed_before: bool,
}

fn swap_pre_staged_file(
    sibling_tmp: &Path,
    target: &Path,
    max_attempts: usize,
    retry_delay: Duration,
) -> Result<CompletedSwap> {
    let backup = backup_path_for(target);
    let mut last_err = String::new();
    let attempts = max_attempts.max(1);

    for attempt in 0..attempts {
        if backup.exists() {
            let _ = std::fs::remove_file(&backup);
        }

        let existed_before = target.exists();
        if existed_before {
            if let Err(e) = std::fs::rename(target, &backup) {
                last_err = format!("rename old to backup: {}", e);
                if attempt + 1 < attempts {
                    std::thread::sleep(retry_delay);
                }
                continue;
            }
        }

        match std::fs::rename(sibling_tmp, target) {
            Ok(()) => {
                return Ok(CompletedSwap {
                    target: target.to_path_buf(),
                    backup,
                    existed_before,
                });
            }
            Err(e) => {
                last_err = format!("rename new to target: {}", e);
                if existed_before {
                    let _ = std::fs::rename(&backup, target);
                }
                if attempt + 1 < attempts {
                    std::thread::sleep(retry_delay);
                }
            }
        }
    }

    Err(anyhow!(
        "Failed to replace {} after {} attempts: {}",
        target.display(),
        attempts,
        last_err
    ))
}

fn rollback_completed_swaps(completed: Vec<CompletedSwap>) {
    for done in completed.into_iter().rev() {
        let failed_tmp = done.target.with_extension("rollback.tmp");
        let _ = std::fs::remove_file(&failed_tmp);
        if done.existed_before {
            if done.target.exists() && std::fs::rename(&done.target, &failed_tmp).is_err() {
                let _ = std::fs::remove_file(&done.target);
            }
            if done.backup.exists() {
                let _ = std::fs::rename(&done.backup, &done.target);
            }
            let _ = std::fs::remove_file(&failed_tmp);
        } else if done.target.exists() {
            let _ = std::fs::remove_file(&done.target);
        }
    }
}

/// Atomically swaps `target` with `staged` using a same-volume temporary copy and `.prev` backup
/// with automatic rollback if finalization fails.
pub fn replace_binary_atomically(staged: &Path, target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("Target path has no parent: {}", target.display()))?;
    std::fs::create_dir_all(parent)?;

    let sibling_tmp = sibling_tmp_path_for(target);
    let _ = std::fs::remove_file(&sibling_tmp);
    std::fs::copy(staged, &sibling_tmp)
        .with_context(|| format!("Failed to copy staged binary to {}", sibling_tmp.display()))?;

    let res = swap_pre_staged_file(
        &sibling_tmp,
        target,
        DEFAULT_SWAP_MAX_ATTEMPTS,
        Duration::from_millis(DEFAULT_SWAP_RETRY_DELAY_MS),
    );
    if res.is_err() {
        let _ = std::fs::remove_file(&sibling_tmp);
    }
    res.map(|_| ())
}

/// Atomically swaps a batch of `(staged, target)` files with full transactional rollback:
/// if ANY single file fails to swap, every previously swapped file in the batch is restored
/// from its `.prev` backup (or removed if newly created).
pub fn replace_batch_atomically(pairs: &[(PathBuf, PathBuf)]) -> Result<()> {
    replace_batch_atomically_internal(
        pairs,
        DEFAULT_SWAP_MAX_ATTEMPTS,
        Duration::from_millis(DEFAULT_SWAP_RETRY_DELAY_MS),
        |_, _| Ok(()),
    )
}

fn replace_batch_atomically_internal<F>(
    pairs: &[(PathBuf, PathBuf)],
    max_attempts: usize,
    retry_delay: Duration,
    mut before_swap_hook: F,
) -> Result<()>
where
    F: FnMut(usize, &Path) -> Result<()>,
{
    if pairs.is_empty() {
        return Ok(());
    }

    // Phase 1: pre-copy every staged file into its same-volume sibling `.new.tmp`
    // so read/disk errors abort cleanly before any live file is touched.
    let mut prepared: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(pairs.len());
    for (staged, target) in pairs {
        if !staged.is_file() {
            for (tmp, _) in &prepared {
                let _ = std::fs::remove_file(tmp);
            }
            bail!("Staged file missing: {}", staged.display());
        }
        let parent = target
            .parent()
            .ok_or_else(|| anyhow!("Target path has no parent: {}", target.display()))?;
        if let Err(e) = std::fs::create_dir_all(parent) {
            for (tmp, _) in &prepared {
                let _ = std::fs::remove_file(tmp);
            }
            return Err(e.into());
        }
        let sibling_tmp = sibling_tmp_path_for(target);
        let _ = std::fs::remove_file(&sibling_tmp);
        if let Err(e) = std::fs::copy(staged, &sibling_tmp).with_context(|| {
            format!(
                "Failed to stage {} -> {}",
                staged.display(),
                sibling_tmp.display()
            )
        }) {
            for (tmp, _) in &prepared {
                let _ = std::fs::remove_file(tmp);
            }
            return Err(e);
        }
        prepared.push((sibling_tmp, target.clone()));
    }

    // Phase 2: swap all targets sequentially; on any error, roll back every completed target.
    let mut completed: Vec<CompletedSwap> = Vec::with_capacity(prepared.len());
    for (idx, (sibling_tmp, target)) in prepared.iter().enumerate() {
        let hook_res = before_swap_hook(idx, target);
        let swap_res = match hook_res {
            Ok(()) => swap_pre_staged_file(sibling_tmp, target, max_attempts, retry_delay),
            Err(e) => Err(e),
        };
        match swap_res {
            Ok(done) => completed.push(done),
            Err(err) => {
                rollback_completed_swaps(completed);
                for (remaining_tmp, _) in &prepared[idx..] {
                    let _ = std::fs::remove_file(remaining_tmp);
                }
                return Err(err);
            }
        }
    }

    Ok(())
}

/// Abstracts `BypaxService` stop/start coordination so multi-binary updates release file locks
/// cleanly in production and can be deterministically verified in unit tests.
pub trait ServiceLifecycleController {
    fn is_service_running(&self) -> bool;
    fn stop_service_gracefully(&self) -> Result<()>;
    fn start_service(&self) -> Result<()>;
}

pub struct OsServiceLifecycleController {
    #[cfg_attr(not(windows), allow(dead_code))]
    service_name: String,
}

impl OsServiceLifecycleController {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

#[cfg(windows)]
fn try_plane1_graceful_stop() {
    // Best-effort Plane 1 stop before SCM STOP so WinDivert handles and child proxy
    // processes flush cleanly. Silently ignored if service IPC is unreachable.
    use std::io::Write;
    let token = bypax_ipc::load_ipc_token(None).unwrap_or_default();
    for (idx, cmd) in [
        bypax_ipc::ServiceCommand::StopAppProxy,
        bypax_ipc::ServiceCommand::StopCore,
    ]
    .into_iter()
    .enumerate()
    {
        if let Ok(mut pipe) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(bypax_ipc::WINDOWS_SVC_PIPE_NAME)
        {
            let env = bypax_ipc::ServiceEnvelope {
                id: format!("updater-stop-{}", idx),
                session_token: token.clone(),
                command: cmd,
            };
            if let Ok(mut line) = serde_json::to_string(&env) {
                line.push('\n');
                let _ = pipe.write_all(line.as_bytes());
                let _ = pipe.flush();
            }
        }
    }
    std::thread::sleep(Duration::from_millis(200));
}

#[cfg(windows)]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
impl ServiceLifecycleController for OsServiceLifecycleController {
    fn is_service_running(&self) -> bool {
        use windows::core::PCWSTR;
        use windows::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
            SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
            SERVICE_STATUS,
        };

        let svc_wide = to_wide_null(&self.service_name);
        unsafe {
            let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
            else {
                return false;
            };
            let Ok(svc) = OpenServiceW(scm, PCWSTR(svc_wide.as_ptr()), SERVICE_QUERY_STATUS)
            else {
                let _ = CloseServiceHandle(scm);
                return false;
            };
            let mut status = SERVICE_STATUS::default();
            let running = QueryServiceStatus(svc, &mut status).is_ok()
                && (status.dwCurrentState == SERVICE_RUNNING
                    || status.dwCurrentState == SERVICE_START_PENDING);
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
            running
        }
    }

    fn stop_service_gracefully(&self) -> Result<()> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Services::{
            CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
            SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATUS,
            SERVICE_STOP, SERVICE_STOPPED,
        };

        try_plane1_graceful_stop();

        let svc_wide = to_wide_null(&self.service_name);
        unsafe {
            let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
                .context("Failed to open Windows SCM to stop BypaxService")?;
            let svc = match OpenServiceW(
                scm,
                PCWSTR(svc_wide.as_ptr()),
                SERVICE_STOP | SERVICE_QUERY_STATUS,
            ) {
                Ok(h) => h,
                Err(e) => {
                    let _ = CloseServiceHandle(scm);
                    bail!("Failed to open service {} for stop: {}", self.service_name, e);
                }
            };

            let mut status = SERVICE_STATUS::default();
            if QueryServiceStatus(svc, &mut status).is_ok()
                && status.dwCurrentState == SERVICE_STOPPED
            {
                let _ = CloseServiceHandle(svc);
                let _ = CloseServiceHandle(scm);
                return Ok(());
            }

            let ctrl_res = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
            if let Err(e) = ctrl_res {
                let _ = CloseServiceHandle(svc);
                let _ = CloseServiceHandle(scm);
                bail!(
                    "Failed to send STOP control to {}: {}",
                    self.service_name,
                    e
                );
            }

            // Wait up to 15 seconds for full shutdown and file handle release.
            let mut stopped = false;
            for _ in 0..60 {
                std::thread::sleep(Duration::from_millis(250));
                let mut st = SERVICE_STATUS::default();
                if QueryServiceStatus(svc, &mut st).is_ok()
                    && st.dwCurrentState == SERVICE_STOPPED
                {
                    stopped = true;
                    break;
                }
            }
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
            if !stopped {
                bail!("Timed out waiting for {} to stop", self.service_name);
            }
        }
        std::thread::sleep(Duration::from_millis(300));
        Ok(())
    }

    fn start_service(&self) -> Result<()> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, StartServiceW,
            SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
            SERVICE_STATUS,
        };

        let svc_wide = to_wide_null(&self.service_name);
        unsafe {
            let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
                .context("Failed to open Windows SCM to start BypaxService")?;
            let svc = match OpenServiceW(
                scm,
                PCWSTR(svc_wide.as_ptr()),
                SERVICE_START | SERVICE_QUERY_STATUS,
            ) {
                Ok(h) => h,
                Err(e) => {
                    let _ = CloseServiceHandle(scm);
                    bail!(
                        "Failed to open service {} for start: {}",
                        self.service_name,
                        e
                    );
                }
            };

            let mut status = SERVICE_STATUS::default();
            if QueryServiceStatus(svc, &mut status).is_ok()
                && status.dwCurrentState == SERVICE_RUNNING
            {
                let _ = CloseServiceHandle(svc);
                let _ = CloseServiceHandle(scm);
                return Ok(());
            }

            if let Err(e) = StartServiceW(svc, None) {
                let _ = CloseServiceHandle(svc);
                let _ = CloseServiceHandle(scm);
                bail!("Failed to start {}: {}", self.service_name, e);
            }

            for _ in 0..40 {
                std::thread::sleep(Duration::from_millis(250));
                let mut st = SERVICE_STATUS::default();
                if QueryServiceStatus(svc, &mut st).is_ok()
                    && st.dwCurrentState == SERVICE_RUNNING
                {
                    break;
                }
            }
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl ServiceLifecycleController for OsServiceLifecycleController {
    fn is_service_running(&self) -> bool {
        false
    }

    fn stop_service_gracefully(&self) -> Result<()> {
        Ok(())
    }

    fn start_service(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
fn wait_for_pid_exit(pid: u32, timeout_ms: u32) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};

    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
            let _ = WaitForSingleObject(handle, timeout_ms);
            let _ = CloseHandle(handle);
        }
    }
    std::thread::sleep(Duration::from_millis(300));
}

#[cfg(not(windows))]
fn wait_for_pid_exit(_pid: u32, _timeout_ms: u32) {
    std::thread::sleep(Duration::from_millis(800));
}

fn write_apply_result(path: &Path, result: &UpdateApplyResult) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(result) {
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// Builds the relaunch command arguments for `plan` after update completion or rollback.
pub fn build_relaunch_args(plan: &UpdatePlan, helper_exe: Option<&Path>) -> Vec<String> {
    let mut args = vec![RESUME_AFTER_UPDATE_ARG.to_string()];
    if plan.resume_core {
        args.push(RESUME_CORE_ARG.to_string());
    }
    if plan.resume_sys_proxy {
        args.push(RESUME_SYS_PROXY_ARG.to_string());
    }
    if plan.resume_app_proxy {
        args.push(RESUME_APP_PROXY_ARG.to_string());
    }
    if plan.resume_tun {
        args.push(RESUME_TUN_ARG.to_string());
    }
    if let Some(helper) = helper_exe {
        args.push(CLEANUP_HELPER_ARG.to_string());
        args.push(helper.to_string_lossy().to_string());
    }
    args
}

fn relaunch_target(plan: &UpdatePlan, helper_exe: Option<&Path>) {
    let mut cmd = std::process::Command::new(&plan.target_exe);
    cmd.args(build_relaunch_args(plan, helper_exe))
        .current_dir(&plan.target_dir);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    let _ = cmd.spawn();
}

/// Collects the full ordered list of `(staged_src, target_dst)` pairs for an `UpdatePlan`,
/// plus a flag indicating whether `BypaxService` must be stopped before replacing locked files.
pub fn build_swap_manifest(plan: &UpdatePlan) -> (Vec<(PathBuf, PathBuf)>, bool) {
    let mut pairs: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut seen_targets: Vec<PathBuf> = Vec::new();
    let mut needs_service_stop = false;

    let mut push_unique = |staged: PathBuf, target: PathBuf, stops_service: bool| {
        if !staged.is_file() {
            return;
        }
        if let Ok(rel) = target.strip_prefix(&plan.target_dir) {
            if is_protected_user_data_path(rel) {
                return;
            }
        }
        if seen_targets.iter().any(|p| p == &target) {
            return;
        }
        seen_targets.push(target.clone());
        pairs.push((staged, target));
        if stops_service {
            needs_service_stop = true;
        }
    };

    // Always replace main executable first.
    push_unique(plan.staged_exe.clone(), plan.target_exe.clone(), false);

    if plan.portable_mode || !plan.extra_swaps.is_empty() {
        for swap in &plan.extra_swaps {
            if is_protected_user_data_path(&swap.relative_target) {
                continue;
            }
            let target = plan.target_dir.join(&swap.relative_target);
            push_unique(swap.staged_path.clone(), target, swap.requires_service_stop);
        }

        if let Some(ref cli) = plan.staged_cli_exe {
            push_unique(cli.clone(), plan.target_dir.join("bypax-cli.exe"), false);
        }
        if let Some(ref svc) = plan.staged_service_exe {
            push_unique(
                svc.clone(),
                plan.target_dir.join("bypax-service.exe"),
                true,
            );
        }
        if let Some(ref core) = plan.staged_core_exe {
            push_unique(
                core.clone(),
                plan.target_dir.join("core").join("sing-box.exe"),
                true,
            );
        }

        // Also auto-discover any companion bundle assets alongside `staged_exe`
        // in case the caller constructed a minimal UpdatePlan.
        if let Some(payload_root) = plan.staged_exe.parent() {
            if let Ok(bundle) = discover_staged_bundle_files(payload_root, false) {
                for swap in bundle.extra_swaps {
                    let target = plan.target_dir.join(&swap.relative_target);
                    push_unique(swap.staged_path, target, swap.requires_service_stop);
                }
            }
            for doc in &plan.docs_to_copy {
                let rel = PathBuf::from(doc);
                if !is_protected_user_data_path(&rel) {
                    push_unique(payload_root.join(&rel), plan.target_dir.join(&rel), false);
                }
            }
        }
    }

    (pairs, needs_service_stop)
}

/// Core multi-binary update transaction with service coordination and atomic rollback.
/// Separated from process waiting/relaunch so integration tests can verify every edge case.
pub fn apply_update_transaction<S, F>(
    plan: &UpdatePlan,
    service_ctl: &S,
    max_attempts: usize,
    retry_delay: Duration,
    before_swap_hook: F,
) -> Result<()>
where
    S: ServiceLifecycleController,
    F: FnMut(usize, &Path) -> Result<()>,
{
    let (pairs, needs_service_stop) = build_swap_manifest(plan);
    let mut service_was_running = false;

    if needs_service_stop && service_ctl.is_service_running() {
        service_was_running = true;
        service_ctl
            .stop_service_gracefully()
            .context("Unable to stop BypaxService before multi-binary replacement")?;
    }

    let swap_result =
        replace_batch_atomically_internal(&pairs, max_attempts, retry_delay, before_swap_hook);

    // Always restore BypaxService if it was active before the update (both on success and rollback).
    if service_was_running {
        let _ = service_ctl.start_service();
    }

    swap_result
}

/// Executes an `UpdatePlan` inside the detached helper process.
pub fn apply_update_plan(plan_path: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(plan_path)?;
    let plan: UpdatePlan = serde_json::from_str(&raw)?;
    let self_exe = std::env::current_exe().ok();

    wait_for_pid_exit(plan.parent_pid, 20_000);

    let svc_name = plan
        .service_name
        .clone()
        .unwrap_or_else(|| BYPAX_SERVICE_NAME.to_string());
    let service_ctl = OsServiceLifecycleController::new(svc_name);

    match apply_update_transaction(
        &plan,
        &service_ctl,
        DEFAULT_SWAP_MAX_ATTEMPTS,
        Duration::from_millis(DEFAULT_SWAP_RETRY_DELAY_MS),
        |_, _| Ok(()),
    ) {
        Ok(()) => {
            let res = UpdateApplyResult {
                success: true,
                from_version: plan.from_version.clone(),
                to_version: plan.to_version.clone(),
                to_tag: plan.to_tag.clone(),
                error: None,
                applied_at: chrono::Utc::now().to_rfc3339(),
            };
            write_apply_result(&plan.result_file, &res);
            relaunch_target(&plan, self_exe.as_deref());

            let _ = std::fs::remove_dir_all(&plan.staged_dir);
            let _ = std::fs::remove_file(plan_path);
            Ok(())
        }
        Err(e) => {
            let res = UpdateApplyResult {
                success: false,
                from_version: plan.from_version.clone(),
                to_version: plan.to_version.clone(),
                to_tag: plan.to_tag.clone(),
                error: Some(e.to_string()),
                applied_at: chrono::Utc::now().to_rfc3339(),
            };
            write_apply_result(&plan.result_file, &res);
            // Relaunch the preserved original executable so the user is never stranded.
            relaunch_target(&plan, self_exe.as_deref());
            let _ = std::fs::remove_file(plan_path);
            Err(e)
        }
    }
}

fn cleanup_prev_backups_in_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if name.contains(".prev.") || name.ends_with(".prev") || name.ends_with(".new.tmp") {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

/// Cleans up leftover temporary updater helper binaries, `.prev` backups across all bundle dirs,
/// and old staging directories.
pub fn cleanup_post_update_artifacts(args: &[String], updates_root: &Path) {
    if let Some(idx) = args.iter().position(|a| a == CLEANUP_HELPER_ARG) {
        if let Some(helper_path) = args.get(idx + 1) {
            let p = PathBuf::from(helper_path);
            for _ in 0..8 {
                if !p.exists() || std::fs::remove_file(&p).is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            cleanup_prev_backups_in_dir(parent);
            cleanup_prev_backups_in_dir(&parent.join("core"));
            cleanup_prev_backups_in_dir(&parent.join("runtime").join("windivert"));
            cleanup_prev_backups_in_dir(&parent.join("skills").join("bypax-agent"));
        }
    }

    if updates_root.is_dir() {
        if let Ok(entries) = std::fs::read_dir(updates_root) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    let _ = std::fs::remove_dir_all(p);
                } else {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
    }
}

/// Reads and deletes `runtime/last-update-result.json` if present.
pub fn take_last_update_result(result_file: &Path) -> Option<UpdateApplyResult> {
    let raw = std::fs::read_to_string(result_file).ok()?;
    let _ = std::fs::remove_file(result_file);
    serde_json::from_str(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct MockServiceController {
        running: Mutex<bool>,
        events: Mutex<Vec<&'static str>>,
        fail_stop: bool,
    }

    impl MockServiceController {
        fn new(running: bool) -> Self {
            Self {
                running: Mutex::new(running),
                events: Mutex::new(Vec::new()),
                fail_stop: false,
            }
        }

        fn recorded_events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }
    }

    impl ServiceLifecycleController for MockServiceController {
        fn is_service_running(&self) -> bool {
            *self.running.lock().unwrap()
        }

        fn stop_service_gracefully(&self) -> Result<()> {
            self.events.lock().unwrap().push("stop");
            if self.fail_stop {
                bail!("simulated SCM stop failure");
            }
            *self.running.lock().unwrap() = false;
            Ok(())
        }

        fn start_service(&self) -> Result<()> {
            self.events.lock().unwrap().push("start");
            *self.running.lock().unwrap() = true;
            Ok(())
        }
    }

    fn write_fake_pe(path: &Path, size: usize, marker: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut bytes = vec![0u8; size];
        bytes[0..2].copy_from_slice(b"MZ");
        let offset: u32 = 128;
        bytes[60..64].copy_from_slice(&offset.to_le_bytes());
        bytes[128..132].copy_from_slice(b"PE\0\0");
        let end = (160 + marker.len()).min(size);
        bytes[160..end].copy_from_slice(&marker[..(end - 160)]);
        std::fs::write(path, &bytes).unwrap();
    }

    #[test]
    fn compares_semver_versions_accurately() {
        assert_eq!(compare_versions("0.2.0", "0.1.0"), Ordering::Greater);
        assert_eq!(compare_versions("v0.10.0", "v0.2.9"), Ordering::Greater);
        assert_eq!(compare_versions("0.2.0", "0.2.0-rc.1"), Ordering::Greater);
        assert_eq!(compare_versions("0.1.0", "v0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.1.0", "0.1.1"), Ordering::Less);
    }

    #[test]
    fn normalizes_windows_proxy_server_formats() {
        assert_eq!(
            normalize_proxy_url("127.0.0.1:7897").as_deref(),
            Some("http://127.0.0.1:7897")
        );
        assert_eq!(
            normalize_proxy_url("http=127.0.0.1:7890;https=127.0.0.1:7891").as_deref(),
            Some("http://127.0.0.1:7891")
        );
        assert_eq!(
            normalize_proxy_url("socks=127.0.0.1:10808").as_deref(),
            Some("socks5://127.0.0.1:10808")
        );
        assert!(normalize_proxy_url("   ").is_none());
    }

    #[test]
    fn parses_sha256sums_strictly() {
        let valid_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let content = format!(
            "# comment\n{}  bypax-v0.2.0-x86_64-windows-portable.zip\nBADHASH  other.exe\n",
            valid_hash.to_ascii_uppercase()
        );
        assert_eq!(
            parse_sha256sums(&content, "bypax-v0.2.0-x86_64-windows-portable.zip").as_deref(),
            Some(valid_hash)
        );
        assert!(parse_sha256sums(&content, "other.exe").is_none());
        assert!(parse_sha256sums(&content, "missing.exe").is_none());
    }

    #[test]
    fn parses_release_json_portable_vs_standalone_and_rejects_untrusted_urls() {
        let json = r#"{
            "tag_name": "v0.2.0",
            "name": "Bypax v0.2.0",
            "html_url": "https://github.com/Nexusyyan/bypax/releases/tag/v0.2.0",
            "published_at": "2026-11-26T08:00:00Z",
            "body": "Multi-binary self-update",
            "assets": [
                {
                    "name": "bypax-v0.2.0-x86_64-windows-nodriver.zip",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.2.0/bypax-v0.2.0-x86_64-windows-nodriver.zip",
                    "size": 21000000
                },
                {
                    "name": "bypax-v0.2.0-x86_64-windows-portable.zip",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.2.0/bypax-v0.2.0-x86_64-windows-portable.zip",
                    "size": 22000000
                },
                {
                    "name": "bypax-v0.2.0-x86_64-windows.exe",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.2.0/bypax-v0.2.0-x86_64-windows.exe",
                    "size": 7500000
                },
                {
                    "name": "SHA256SUMS.txt",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.2.0/SHA256SUMS.txt",
                    "size": 256
                }
            ]
        }"#;

        // Portable mode always prefers the full portable bundle so CLI/service/drivers upgrade together.
        let report_portable =
            parse_app_release_json("0.1.0", json, "proxy:bypax", true, true).unwrap();
        assert!(report_portable.update_available);
        assert_eq!(
            report_portable.selected_asset_name.as_deref(),
            Some("bypax-v0.2.0-x86_64-windows-portable.zip")
        );
        assert_eq!(
            report_portable.selected_asset_kind.as_deref(),
            Some("portable_zip")
        );
        assert!(report_portable.checksums_url.is_some());

        // Non-portable with companion binaries also prefers portable bundle.
        let report_companions =
            parse_app_release_json_with_layout("0.1.0", json, "direct", false, true).unwrap();
        assert_eq!(
            report_companions.selected_asset_kind.as_deref(),
            Some("portable_zip")
        );

        // Pure single-file standalone install selects lightweight standalone EXE.
        let report_standalone =
            parse_app_release_json("0.1.0", json, "direct", false, true).unwrap();
        assert_eq!(
            report_standalone.selected_asset_name.as_deref(),
            Some("bypax-v0.2.0-x86_64-windows.exe")
        );
        assert_eq!(
            report_standalone.selected_asset_kind.as_deref(),
            Some("standalone_exe")
        );

        // Untrusted third-party URLs must be rejected.
        let evil = r#"{
            "tag_name": "v0.9.0",
            "html_url": "https://evil.example.com/fake",
            "assets": [{
                "name": "bypax-v0.9.0-x86_64-windows.exe",
                "browser_download_url": "https://evil.example.com/malware.exe",
                "size": 999
            }]
        }"#;
        let evil_rep = parse_app_release_json("0.1.0", evil, "direct", false, true).unwrap();
        assert_eq!(evil_rep.release_url, RELEASES_PAGE_URL);
        assert!(evil_rep.selected_asset_url.is_none());
        assert!(!evil_rep.in_app_update_supported);
    }

    #[test]
    fn extract_zip_safely_blocks_zip_slip_and_preserves_bypax_user_data() {
        let dir = tempdir().unwrap();
        let bad_zip = dir.path().join("slip.zip");
        {
            let f = std::fs::File::create(&bad_zip).unwrap();
            let mut w = zip::ZipWriter::new(f);
            let opts = zip::write::SimpleFileOptions::default();
            w.start_file("../escape.txt", opts).unwrap();
            w.write_all(b"pwned").unwrap();
            w.finish().unwrap();
        }
        assert!(extract_zip_safely(&bad_zip, &dir.path().join("out-bad")).is_err());

        let good_zip = dir.path().join("good.zip");
        {
            let f = std::fs::File::create(&good_zip).unwrap();
            let mut w = zip::ZipWriter::new(f);
            let opts = zip::write::SimpleFileOptions::default();
            w.start_file("bypax.exe", opts).unwrap();
            w.write_all(b"exe-body").unwrap();
            w.start_file("bypax-cli.exe", opts).unwrap();
            w.write_all(b"cli-body").unwrap();
            w.start_file("bypax-service.exe", opts).unwrap();
            w.write_all(b"svc-body").unwrap();
            w.start_file("skills/bypax-agent/SKILL.md", opts).unwrap();
            w.write_all(b"# Bypax Agent Skill").unwrap();
            w.start_file("portable.json", opts).unwrap();
            w.write_all(b"{\"portable\":true}").unwrap();
            w.start_file("bypax-data/bypax.db", opts).unwrap();
            w.write_all(b"should-be-skipped").unwrap();
            w.finish().unwrap();
        }
        let out_good = dir.path().join("out-good");
        extract_zip_safely(&good_zip, &out_good).unwrap();
        assert!(out_good.join("bypax.exe").is_file());
        assert!(out_good.join("bypax-cli.exe").is_file());
        assert!(out_good.join("bypax-service.exe").is_file());
        assert!(out_good.join("skills/bypax-agent/SKILL.md").is_file());
        assert!(!out_good.join("portable.json").exists());
        assert!(!out_good.join("bypax-data").exists());
    }

    #[test]
    fn replace_binary_atomically_swaps_and_creates_backup() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("bypax.exe");
        let staged = dir.path().join("staged.exe");
        std::fs::write(&target, b"old-version-binary").unwrap();
        std::fs::write(&staged, b"new-version-binary").unwrap();

        replace_binary_atomically(&staged, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new-version-binary");
        assert_eq!(
            std::fs::read(dir.path().join("bypax.prev.exe")).unwrap(),
            b"old-version-binary"
        );
    }

    #[test]
    fn validates_pe_header_and_driver_images() {
        let dir = tempdir().unwrap();
        let bad = dir.path().join("bad.exe");
        std::fs::write(&bad, vec![0u8; 70_000]).unwrap();
        assert!(validate_pe_header(&bad).is_err());

        let good = dir.path().join("good.exe");
        write_fake_pe(&good, 70_000, b"bypax-v2");
        assert!(validate_pe_header(&good).is_ok());

        let small_drv = dir.path().join("WinDivert.dll");
        write_fake_pe(&small_drv, 24_000, b"windivert-dll");
        assert!(validate_pe_header(&small_drv).is_err());
        assert!(validate_pe_image(&small_drv, MIN_DRIVER_PE_BYTES).is_ok());
    }

    #[test]
    fn multi_binary_portable_swap_coordinates_service_and_preserves_user_data() {
        let dir = tempdir().unwrap();
        let install_dir = dir.path().join("install");
        let staged_dir = dir.path().join("stage");
        let payload_dir = staged_dir.join("payload");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::create_dir_all(&payload_dir).unwrap();

        // Populate existing installation including user data that must remain untouched.
        write_fake_pe(&install_dir.join("bypax.exe"), 70_000, b"OLD_GUI");
        write_fake_pe(&install_dir.join("bypax-cli.exe"), 70_000, b"OLD_CLI");
        write_fake_pe(&install_dir.join("bypax-service.exe"), 70_000, b"OLD_SVC");
        write_fake_pe(
            &install_dir.join("core").join("sing-box.exe"),
            70_000,
            b"OLD_CORE",
        );
        write_fake_pe(
            &install_dir.join("runtime/windivert/WinDivert.dll"),
            20_000,
            b"OLD_WD_DLL",
        );
        write_fake_pe(
            &install_dir.join("runtime/windivert/WinDivert64.sys"),
            20_000,
            b"OLD_WD_SYS",
        );
        std::fs::create_dir_all(install_dir.join("skills/bypax-agent")).unwrap();
        std::fs::write(
            install_dir.join("skills/bypax-agent/SKILL.md"),
            b"old skill",
        )
        .unwrap();
        std::fs::create_dir_all(install_dir.join("bypax-data")).unwrap();
        std::fs::write(install_dir.join("bypax-data/bypax.db"), b"USER_DB_SAFE").unwrap();
        std::fs::write(install_dir.join("portable.json"), b"{\"portable\":true}").unwrap();

        // Populate staged v0.2.0 bundle.
        write_fake_pe(&payload_dir.join("bypax.exe"), 70_000, b"NEW_GUI");
        write_fake_pe(&payload_dir.join("bypax-cli.exe"), 70_000, b"NEW_CLI");
        write_fake_pe(&payload_dir.join("bypax-service.exe"), 70_000, b"NEW_SVC");
        write_fake_pe(
            &payload_dir.join("core").join("sing-box.exe"),
            70_000,
            b"NEW_CORE",
        );
        write_fake_pe(
            &payload_dir.join("runtime/windivert/WinDivert.dll"),
            20_000,
            b"NEW_WD_DLL",
        );
        write_fake_pe(
            &payload_dir.join("runtime/windivert/WinDivert64.sys"),
            20_000,
            b"NEW_WD_SYS",
        );
        std::fs::create_dir_all(payload_dir.join("skills/bypax-agent")).unwrap();
        std::fs::write(
            payload_dir.join("skills/bypax-agent/SKILL.md"),
            b"new skill v2",
        )
        .unwrap();

        let bundle = discover_staged_bundle_files(&payload_dir, true).unwrap();
        assert!(bundle.cli_exe.is_some());
        assert!(bundle.service_exe.is_some());
        assert!(bundle.core_exe.is_some());
        assert!(bundle.extra_swaps.len() >= 6);

        let plan = UpdatePlan {
            parent_pid: 0,
            target_exe: install_dir.join("bypax.exe"),
            target_dir: install_dir.clone(),
            portable_mode: true,
            staged_dir: staged_dir.clone(),
            staged_exe: payload_dir.join("bypax.exe"),
            staged_core_exe: bundle.core_exe,
            staged_cli_exe: bundle.cli_exe,
            staged_service_exe: bundle.service_exe,
            extra_swaps: bundle.extra_swaps,
            docs_to_copy: vec![],
            resume_core: true,
            resume_sys_proxy: false,
            resume_app_proxy: true,
            resume_tun: false,
            service_name: Some(BYPAX_SERVICE_NAME.to_string()),
            from_version: "0.1.0".to_string(),
            to_version: "0.2.0".to_string(),
            to_tag: "v0.2.0".to_string(),
            result_file: install_dir.join("bypax-data/runtime/last-update-result.json"),
        };

        let mock_svc = MockServiceController::new(true);
        apply_update_transaction(&plan, &mock_svc, 3, Duration::from_millis(5), |_, _| Ok(()))
            .unwrap();

        // Service was stopped before swap and restarted after swap.
        assert_eq!(mock_svc.recorded_events(), vec!["stop", "start"]);
        assert!(mock_svc.is_service_running());

        // All binaries & skills updated.
        assert!(&std::fs::read(install_dir.join("bypax.exe")).unwrap()[160..167] == b"NEW_GUI");
        assert!(
            &std::fs::read(install_dir.join("bypax-cli.exe")).unwrap()[160..167] == b"NEW_CLI"
        );
        assert!(
            &std::fs::read(install_dir.join("bypax-service.exe")).unwrap()[160..167] == b"NEW_SVC"
        );
        assert!(
            &std::fs::read(install_dir.join("core/sing-box.exe")).unwrap()[160..168] == b"NEW_CORE"
        );
        assert!(
            &std::fs::read(install_dir.join("runtime/windivert/WinDivert64.sys")).unwrap()
                [160..170]
                == b"NEW_WD_SYS"
        );
        assert_eq!(
            std::fs::read(install_dir.join("skills/bypax-agent/SKILL.md")).unwrap(),
            b"new skill v2"
        );

        // User data & portable.json preserved intact.
        assert_eq!(
            std::fs::read(install_dir.join("bypax-data/bypax.db")).unwrap(),
            b"USER_DB_SAFE"
        );
        assert_eq!(
            std::fs::read(install_dir.join("portable.json")).unwrap(),
            b"{\"portable\":true}"
        );

        // Relaunch args include app-proxy resume flag.
        let relaunch = build_relaunch_args(&plan, None);
        assert!(relaunch.contains(&RESUME_AFTER_UPDATE_ARG.to_string()));
        assert!(relaunch.contains(&RESUME_CORE_ARG.to_string()));
        assert!(relaunch.contains(&RESUME_APP_PROXY_ARG.to_string()));
        assert!(!relaunch.contains(&RESUME_TUN_ARG.to_string()));
    }

    #[test]
    fn injected_lock_failure_rolls_back_entire_multi_binary_batch_and_restarts_service() {
        let dir = tempdir().unwrap();
        let install_dir = dir.path().join("install");
        let payload_dir = dir.path().join("payload");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::create_dir_all(&payload_dir).unwrap();

        write_fake_pe(&install_dir.join("bypax.exe"), 70_000, b"OLD_GUI");
        write_fake_pe(&install_dir.join("bypax-cli.exe"), 70_000, b"OLD_CLI");
        write_fake_pe(&install_dir.join("bypax-service.exe"), 70_000, b"OLD_SVC");
        write_fake_pe(
            &install_dir.join("runtime/windivert/WinDivert64.sys"),
            20_000,
            b"OLD_WD_SYS",
        );

        write_fake_pe(&payload_dir.join("bypax.exe"), 70_000, b"NEW_GUI");
        write_fake_pe(&payload_dir.join("bypax-cli.exe"), 70_000, b"NEW_CLI");
        write_fake_pe(&payload_dir.join("bypax-service.exe"), 70_000, b"NEW_SVC");
        write_fake_pe(
            &payload_dir.join("runtime/windivert/WinDivert64.sys"),
            20_000,
            b"NEW_WD_SYS",
        );
        // Also add a brand-new file that did not exist before; rollback must remove it too.
        std::fs::create_dir_all(payload_dir.join("skills/bypax-agent")).unwrap();
        std::fs::write(
            payload_dir.join("skills/bypax-agent/SKILL.md"),
            b"brand new file",
        )
        .unwrap();

        let bundle = discover_staged_bundle_files(&payload_dir, true).unwrap();
        let plan = UpdatePlan {
            parent_pid: 0,
            target_exe: install_dir.join("bypax.exe"),
            target_dir: install_dir.clone(),
            portable_mode: true,
            staged_dir: dir.path().join("stage"),
            staged_exe: payload_dir.join("bypax.exe"),
            staged_core_exe: bundle.core_exe,
            staged_cli_exe: bundle.cli_exe,
            staged_service_exe: bundle.service_exe,
            extra_swaps: bundle.extra_swaps,
            docs_to_copy: vec![],
            resume_core: true,
            resume_sys_proxy: false,
            resume_app_proxy: false,
            resume_tun: true,
            service_name: Some(BYPAX_SERVICE_NAME.to_string()),
            from_version: "0.1.0".to_string(),
            to_version: "0.2.0".to_string(),
            to_tag: "v0.2.0".to_string(),
            result_file: install_dir.join("result.json"),
        };

        let mock_svc = MockServiceController::new(true);
        // Inject a lock failure right when swapping WinDivert64.sys (after bypax.exe, bypax-cli.exe, bypax-service.exe already swapped!).
        let err = apply_update_transaction(&plan, &mock_svc, 2, Duration::from_millis(5), |_, dst| {
            if dst
                .file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.eq_ignore_ascii_case("WinDivert64.sys"))
                .unwrap_or(false)
            {
                bail!("simulated sharing violation lock on WinDivert64.sys");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(err.to_string().contains("WinDivert64.sys"));

        // Service MUST still be restarted after rollback.
        assert_eq!(mock_svc.recorded_events(), vec!["stop", "start"]);
        assert!(mock_svc.is_service_running());

        // EVERY earlier binary MUST be rolled back to OLD_*!
        assert!(&std::fs::read(install_dir.join("bypax.exe")).unwrap()[160..167] == b"OLD_GUI");
        assert!(
            &std::fs::read(install_dir.join("bypax-cli.exe")).unwrap()[160..167] == b"OLD_CLI"
        );
        assert!(
            &std::fs::read(install_dir.join("bypax-service.exe")).unwrap()[160..167] == b"OLD_SVC"
        );
        assert!(
            &std::fs::read(install_dir.join("runtime/windivert/WinDivert64.sys")).unwrap()
                [160..170]
                == b"OLD_WD_SYS"
        );
        // Brand-new file must not remain half-installed.
        assert!(!install_dir.join("skills/bypax-agent/SKILL.md").exists());

        // Relaunch args include TUN resume flag.
        let relaunch = build_relaunch_args(&plan, None);
        assert!(relaunch.contains(&RESUME_TUN_ARG.to_string()));
    }
}
