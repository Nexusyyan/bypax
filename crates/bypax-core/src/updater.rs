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
pub const MACOS_LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/com.bypax.service.plist";

const MAX_RELEASE_NOTES_CHARS: usize = 4000;
const MAX_ZIP_ENTRIES: usize = 512;
const MAX_ZIP_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;
const MIN_PE_BYTES: u64 = 64 * 1024;
const MIN_DRIVER_PE_BYTES: u64 = 8 * 1024;
const MIN_MACHO_BYTES: u64 = 64 * 1024;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
pub const MACHO_CPU_TYPE_X86_64: u32 = 0x0100_0007;
pub const MACHO_CPU_TYPE_ARM64: u32 = 0x0100_000C;
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
    pub staged_app_bundle_path: Option<String>,
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
            staged_app_bundle_path: None,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_pid: Option<u32>,
    pub target_exe: PathBuf,
    pub target_dir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_app_bundle: Option<PathBuf>,
    pub portable_mode: bool,
    pub staged_dir: PathBuf,
    pub staged_exe: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_app_bundle: Option<PathBuf>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_dir: Option<PathBuf>,
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
        let target_app_bundle = find_macos_app_bundle_root(&target_exe);
        let staged_app_bundle = staged.staged_app_bundle_path.as_ref().map(PathBuf::from);
        let runtime_dir = result_file.parent().map(|p| p.to_path_buf());
        Self {
            parent_pid,
            helper_pid: None,
            target_exe,
            target_dir,
            target_app_bundle,
            portable_mode,
            staged_dir,
            staged_exe,
            staged_app_bundle,
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
            runtime_dir,
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

    /// Attaches the PID of the running elevated helper (`bypax-service`) so the detached
    /// updater waits for both GUI and helper processes to exit before swapping files.
    pub fn with_helper_pid(mut self, helper_pid: Option<u32>) -> Self {
        self.helper_pid = helper_pid.filter(|&p| p > 0);
        self
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

/// Returns the expected Mach-O 64-bit CPU type for the host macOS architecture.
pub fn expected_host_macho_cputype() -> Option<u32> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Some(MACHO_CPU_TYPE_ARM64)
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        Some(MACHO_CPU_TYPE_X86_64)
    }
    #[cfg(not(all(
        target_os = "macos",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        None
    }
}

/// Validates that a file is a plausible 64-bit Mach-O or Universal (Fat) binary with at least
/// `min_bytes` size, and matches `expected_cputype` when specified.
pub fn validate_macho_binary(
    path: &Path,
    min_bytes: u64,
    expected_cputype: Option<u32>,
) -> Result<()> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("Missing Mach-O binary at {}", path.display()))?;
    if meta.len() < min_bytes {
        bail!(
            "Mach-O binary too small ({} bytes; expected >= {} bytes)",
            meta.len(),
            min_bytes
        );
    }
    let mut f = std::fs::File::open(path)?;
    let mut hdr = [0u8; 8];
    f.read_exact(&mut hdr)?;

    let magic_le = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let magic_be = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);

    if magic_le == MH_MAGIC_64 {
        let cputype = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        if let Some(exp) = expected_cputype {
            if cputype != exp {
                bail!(
                    "Mach-O architecture mismatch for {} (expected 0x{:08x}, got 0x{:08x})",
                    path.display(),
                    exp,
                    cputype
                );
            }
        }
        return Ok(());
    }

    if magic_be == MH_MAGIC_64 {
        let cputype = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        if let Some(exp) = expected_cputype {
            if cputype != exp {
                bail!(
                    "Mach-O architecture mismatch for {} (expected 0x{:08x}, got 0x{:08x})",
                    path.display(),
                    exp,
                    cputype
                );
            }
        }
        return Ok(());
    }

    if magic_be == FAT_MAGIC || magic_be == FAT_MAGIC_64 {
        let nfat = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        if nfat == 0 || nfat > 16 {
            bail!("Invalid Universal Mach-O slice count: {}", nfat);
        }
        let stride = if magic_be == FAT_MAGIC_64 { 32 } else { 20 };
        let mut table = vec![0u8; nfat * stride];
        f.read_exact(&mut table)?;
        if let Some(exp) = expected_cputype {
            let mut matched = false;
            for i in 0..nfat {
                let off = i * stride;
                let cpu = u32::from_be_bytes([
                    table[off],
                    table[off + 1],
                    table[off + 2],
                    table[off + 3],
                ]);
                if cpu == exp {
                    matched = true;
                    break;
                }
            }
            if !matched {
                bail!(
                    "Universal Mach-O binary {} does not contain required architecture 0x{:08x}",
                    path.display(),
                    exp
                );
            }
        }
        return Ok(());
    }

    bail!(
        "Invalid Mach-O header for {} (magic 0x{:08x})",
        path.display(),
        magic_le
    );
}

/// Resolves the enclosing `*.app` bundle root when `exe_path` is located at
/// `<App>.app/Contents/MacOS/<binary>`.
pub fn find_macos_app_bundle_root(exe_path: &Path) -> Option<PathBuf> {
    let macos_dir = exe_path.parent()?;
    if macos_dir.file_name().and_then(|s| s.to_str()) != Some("MacOS") {
        return None;
    }
    let contents_dir = macos_dir.parent()?;
    if contents_dir.file_name().and_then(|s| s.to_str()) != Some("Contents") {
        return None;
    }
    let app_bundle = contents_dir.parent()?;
    let name = app_bundle.file_name().and_then(|s| s.to_str())?;
    if name.len() > 4 && name.to_ascii_lowercase().ends_with(".app") {
        Some(app_bundle.to_path_buf())
    } else {
        None
    }
}

/// Returns `true` when `path` resides inside macOS Gatekeeper App Translocation
/// (read-only randomized mount that cannot be replaced in place).
pub fn is_macos_translocated_path(path: &Path) -> bool {
    path.to_string_lossy().contains("/AppTranslocation/")
}

#[cfg(target_os = "macos")]
fn is_dir_writable_fast(dir: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::access(c_path.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(not(target_os = "macos"))]
fn is_dir_writable_fast(dir: &Path) -> bool {
    std::fs::metadata(dir)
        .map(|m| m.is_dir() && !m.permissions().readonly())
        .unwrap_or(false)
}

/// Returns `true` when `exe_path` belongs to a writable, non-translocated macOS `.app` bundle
/// that can be replaced in place.
pub fn is_macos_app_bundle_updatable(exe_path: &Path) -> bool {
    let Some(bundle) = find_macos_app_bundle_root(exe_path) else {
        return false;
    };
    if is_macos_translocated_path(&bundle) {
        return false;
    }
    let Some(parent) = bundle.parent() else {
        return false;
    };
    is_dir_writable_fast(parent)
}

/// Validates the structure, Mach-O binaries, and (optionally on macOS) deep code signature
/// of a staged `Bypax.app` bundle.
pub fn validate_macos_app_bundle(
    app_bundle: &Path,
    expected_cputype: Option<u32>,
    verify_codesign: bool,
) -> Result<()> {
    if !app_bundle.is_dir() {
        bail!("Staged macOS app bundle missing: {}", app_bundle.display());
    }
    let info_plist = app_bundle.join("Contents").join("Info.plist");
    if !info_plist.is_file() {
        bail!("Staged macOS app bundle missing Contents/Info.plist");
    }
    let macos_dir = app_bundle.join("Contents").join("MacOS");
    let main_exe = macos_dir.join("bypax");
    validate_macho_binary(&main_exe, MIN_MACHO_BYTES, expected_cputype)
        .context("Invalid main executable inside staged Bypax.app")?;

    for companion in [
        macos_dir.join("bypax-cli"),
        macos_dir.join("bypax-service"),
        macos_dir.join("core").join("sing-box"),
    ] {
        if companion.is_file() {
            validate_macho_binary(&companion, MIN_MACHO_BYTES, expected_cputype)
                .with_context(|| format!("Invalid companion Mach-O binary: {}", companion.display()))?;
        }
    }

    if verify_codesign {
        #[cfg(target_os = "macos")]
        {
            let out = std::process::Command::new("/usr/bin/codesign")
                .args(["--verify", "--deep", "--strict"])
                .arg(app_bundle)
                .stdin(std::process::Stdio::null())
                .output()
                .context("Failed to execute codesign --verify on staged Bypax.app")?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                bail!(
                    "Staged Bypax.app failed codesign verification: {}",
                    stderr.trim()
                );
            }
        }
    }
    Ok(())
}

/// Target platform selector used for release asset matching and cross-platform tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePlatform {
    WindowsX64,
    MacosArm64,
    MacosX64,
    Other,
}

impl UpdatePlatform {
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::WindowsX64
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            Self::MacosArm64
        }
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            Self::MacosX64
        }
        #[cfg(not(any(
            target_os = "windows",
            all(target_os = "macos", any(target_arch = "aarch64", target_arch = "x86_64"))
        )))]
        {
            Self::Other
        }
    }
}

/// Detects whether companion binaries (`bypax-cli.exe`, `bypax-service.exe`, or `runtime/windivert`)
/// are installed alongside the main executable, indicating a multi-binary bundle layout.
pub fn has_companion_binaries_in(dir: &Path) -> bool {
    dir.join("bypax-cli.exe").is_file()
        || dir.join("bypax-service.exe").is_file()
        || dir.join("runtime").join("windivert").is_dir()
}

/// Parses GitHub Releases API JSON into a verified `AppUpdateCheckReport` for an explicit target
/// platform and installation writability state.
pub fn parse_app_release_json_for_platform(
    current_version: &str,
    json_body: &str,
    via: &str,
    portable_mode: bool,
    has_companion_binaries: bool,
    platform: UpdatePlatform,
    macos_bundle_updatable: bool,
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
    let mut macos_arm64_dmg: Option<(String, String, u64)> = None;
    let mut macos_x64_dmg: Option<(String, String, u64)> = None;
    let mut macos_universal_dmg: Option<(String, String, u64)> = None;
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
        } else if lower.contains("macos") && lower.ends_with(".dmg") {
            if lower.contains("aarch64") || lower.contains("arm64") {
                macos_arm64_dmg = Some((asset.name, asset.browser_download_url, asset.size));
            } else if lower.contains("x86_64") || lower.contains("amd64") || lower.contains("x64") {
                macos_x64_dmg = Some((asset.name, asset.browser_download_url, asset.size));
            } else if lower.contains("universal") {
                macos_universal_dmg = Some((asset.name, asset.browser_download_url, asset.size));
            }
        }
    }

    let preferred_zip = portable_zip.or(fallback_zip).or(nodriver_zip);
    let prefer_bundle = portable_mode || has_companion_binaries;

    let (selected_asset_kind, selected) = match platform {
        UpdatePlatform::WindowsX64 => {
            if prefer_bundle {
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
            }
        }
        UpdatePlatform::MacosArm64 => match macos_arm64_dmg.or(macos_universal_dmg) {
            Some(d) => (Some("macos_dmg".to_string()), Some(d)),
            None => (None, None),
        },
        UpdatePlatform::MacosX64 => match macos_x64_dmg.or(macos_universal_dmg) {
            Some(d) => (Some("macos_dmg".to_string()), Some(d)),
            None => (None, None),
        },
        UpdatePlatform::Other => (None, None),
    };

    let (selected_asset_name, selected_asset_url, selected_asset_size) = match selected {
        Some((n, u, s)) => (Some(n), Some(u), if s > 0 { Some(s) } else { None }),
        None => (None, None, None),
    };

    let in_app_update_supported = match platform {
        UpdatePlatform::WindowsX64 => selected_asset_url.is_some() && checksums_url.is_some(),
        UpdatePlatform::MacosArm64 | UpdatePlatform::MacosX64 => {
            macos_bundle_updatable
                && selected_asset_kind.as_deref() == Some("macos_dmg")
                && selected_asset_url.is_some()
                && checksums_url.is_some()
        }
        UpdatePlatform::Other => false,
    };

    let install_mode = match platform {
        UpdatePlatform::MacosArm64 | UpdatePlatform::MacosX64 => {
            if macos_bundle_updatable {
                "app_bundle".to_string()
            } else {
                "standalone".to_string()
            }
        }
        _ => {
            if portable_mode {
                "portable".to_string()
            } else {
                "standalone".to_string()
            }
        }
    };

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
        install_mode,
        in_app_update_supported,
        checked_via: via.to_string(),
        checked_at_ms: now_epoch_ms(),
    })
}

/// Parses GitHub Releases API JSON into a verified `AppUpdateCheckReport`.
///
/// Selection strategy:
/// - Windows portable mode or multi-binary bundle installs prefer `portable_zip`.
/// - Windows single-file standalone installs prefer lightweight `standalone_exe`.
/// - macOS Apple Silicon / Intel selects the arch-matched `macos_dmg`.
pub fn parse_app_release_json_with_layout(
    current_version: &str,
    json_body: &str,
    via: &str,
    portable_mode: bool,
    has_companion_binaries: bool,
) -> Result<AppUpdateCheckReport> {
    parse_app_release_json_for_platform(
        current_version,
        json_body,
        via,
        portable_mode,
        has_companion_binaries,
        UpdatePlatform::current(),
        cfg!(target_os = "macos"),
    )
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
    let current_exe = std::env::current_exe().ok();
    let has_companions = current_exe
        .as_deref()
        .and_then(|p| p.parent().map(has_companion_binaries_in))
        .unwrap_or(false);
    let macos_bundle_updatable = current_exe
        .as_deref()
        .map(is_macos_app_bundle_updatable)
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
                install_mode: if cfg!(target_os = "macos") && macos_bundle_updatable {
                    "app_bundle".to_string()
                } else if portable_mode {
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

        return parse_app_release_json_for_platform(
            CURRENT_APP_VERSION,
            &body,
            ch.label(),
            portable_mode,
            has_companions,
            UpdatePlatform::current(),
            macos_bundle_updatable,
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

#[cfg(target_os = "macos")]
struct DmgMountGuard {
    mount_point: PathBuf,
}

#[cfg(target_os = "macos")]
impl Drop for DmgMountGuard {
    fn drop(&mut self) {
        let ok = std::process::Command::new("/usr/bin/hdiutil")
            .args(["detach", "-quiet"])
            .arg(&self.mount_point)
            .stdin(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::process::Command::new("/usr/bin/hdiutil")
                .args(["detach", "-force", "-quiet"])
                .arg(&self.mount_point)
                .stdin(std::process::Stdio::null())
                .status();
        }
        let _ = std::fs::remove_dir(&self.mount_point);
    }
}

/// Mounts a verified macOS DMG read-only at a private mountpoint, copies `Bypax.app` into
/// `dest_payload_dir`, unmounts cleanly, strips quarantine attributes, and validates the
/// Mach-O binaries and deep code signature.
#[cfg(target_os = "macos")]
pub fn extract_macos_dmg_app(dmg_path: &Path, dest_payload_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dest_payload_dir)?;
    let mount_root = dmg_path.parent().unwrap_or(dest_payload_dir);
    let mount_point = mount_root.join(format!(
        "dmg-mount-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir_all(&mount_point)?;

    let attach_out = std::process::Command::new("/usr/bin/hdiutil")
        .args([
            "attach",
            "-nobrowse",
            "-readonly",
            "-noverify",
            "-noautoopen",
            "-mountpoint",
        ])
        .arg(&mount_point)
        .arg(dmg_path)
        .stdin(std::process::Stdio::null())
        .output()
        .context("Failed to execute hdiutil attach")?;
    if !attach_out.status.success() {
        let _ = std::fs::remove_dir(&mount_point);
        let stderr = String::from_utf8_lossy(&attach_out.stderr);
        bail!("Unable to mount macOS update DMG: {}", stderr.trim());
    }

    let guard = DmgMountGuard {
        mount_point: mount_point.clone(),
    };

    let src_app = find_macos_app_in_mount(&mount_point)
        .ok_or_else(|| anyhow!("Bypax.app not found inside macOS update DMG"))?;
    let app_name = src_app
        .file_name()
        .ok_or_else(|| anyhow!("Invalid app bundle name in DMG"))?;
    let dst_app = dest_payload_dir.join(app_name);
    if dst_app.exists() {
        let _ = std::fs::remove_dir_all(&dst_app);
    }

    let ditto_out = std::process::Command::new("/usr/bin/ditto")
        .arg(&src_app)
        .arg(&dst_app)
        .stdin(std::process::Stdio::null())
        .output()
        .context("Failed to copy Bypax.app from mounted DMG")?;
    if !ditto_out.status.success() {
        let _ = std::fs::remove_dir_all(&dst_app);
        let stderr = String::from_utf8_lossy(&ditto_out.stderr);
        bail!("Failed to extract Bypax.app via ditto: {}", stderr.trim());
    }

    // Explicitly detach before validating and returning.
    drop(guard);

    let _ = std::process::Command::new("/usr/bin/xattr")
        .args(["-dr", "com.apple.quarantine"])
        .arg(&dst_app)
        .stdin(std::process::Stdio::null())
        .output();

    if let Err(e) = validate_macos_app_bundle(&dst_app, expected_host_macho_cputype(), true) {
        let _ = std::fs::remove_dir_all(&dst_app);
        return Err(e);
    }

    Ok(dst_app)
}

#[cfg(target_os = "macos")]
fn find_macos_app_in_mount(mount_point: &Path) -> Option<PathBuf> {
    let direct = mount_point.join("Bypax.app");
    if let Ok(meta) = std::fs::symlink_metadata(&direct) {
        if meta.file_type().is_dir() && direct.join("Contents").join("MacOS").join("bypax").is_file()
        {
            return Some(direct);
        }
    }
    let entries = std::fs::read_dir(mount_point).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_dir() {
            continue;
        }
        let is_app = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n.to_ascii_lowercase().ends_with(".app"))
            .unwrap_or(false);
        if is_app && path.join("Contents").join("MacOS").join("bypax").is_file() {
            return Some(path);
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
pub fn extract_macos_dmg_app(_dmg_path: &Path, _dest_payload_dir: &Path) -> Result<PathBuf> {
    bail!("macOS DMG extraction is only supported on macOS");
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
        staged_app_bundle_path: None,
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

    let (
        staged_exe,
        staged_app_bundle,
        staged_cli_exe,
        staged_service_exe,
        staged_core_exe,
        staged_extra_files,
    ) = if asset_kind == "portable_zip" {
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
            None,
            bundle.cli_exe,
            bundle.service_exe,
            bundle.core_exe,
            bundle.extra_swaps,
        )
    } else if asset_kind == "macos_dmg" {
        state.stage = AppUpdateStage::Extracting;
        on_progress(state.clone());
        let dmg_path = stage_dir.join("update.dmg");
        if let Err(e) = std::fs::rename(&part_path, &dmg_path) {
            let _ = std::fs::remove_dir_all(&stage_dir);
            return Err(e.into());
        }
        let staged_app = match extract_macos_dmg_app(&dmg_path, &payload_dir) {
            Ok(app) => app,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
        };
        let _ = std::fs::remove_file(&dmg_path);

        let macos_dir = staged_app.join("Contents").join("MacOS");
        let exe = macos_dir.join("bypax");
        let cli = Some(macos_dir.join("bypax-cli")).filter(|p| p.is_file());
        let svc = Some(macos_dir.join("bypax-service")).filter(|p| p.is_file());
        let core = Some(macos_dir.join("core").join("sing-box")).filter(|p| p.is_file());
        (exe, Some(staged_app), cli, svc, core, Vec::new())
    } else {
        if let Err(e) = validate_pe_header(&part_path) {
            let _ = std::fs::remove_dir_all(&stage_dir);
            return Err(e);
        }
        let exe = payload_dir.join("bypax.exe");
        std::fs::rename(&part_path, &exe)?;
        (exe, None, None, None, None, Vec::new())
    };

    state.stage = AppUpdateStage::ReadyToRestart;
    state.via = Some(final_via);
    state.staged_dir = Some(stage_dir.to_string_lossy().to_string());
    state.staged_exe_path = Some(staged_exe.to_string_lossy().to_string());
    state.staged_app_bundle_path = staged_app_bundle.map(|p| p.to_string_lossy().to_string());
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
        if cfg!(target_os = "macos") {
            format!(
                "Installation folder {} is not writable; move Bypax.app to a writable directory such as /Applications or ~/Applications",
                target_dir.display()
            )
        } else {
            format!(
                "Installation folder {} is not writable; move Bypax to a writable directory or run as administrator",
                target_dir.display()
            )
        }
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Copies the current executable into a detached helper binary and launches it to apply `plan`
/// after this process exits.
pub fn spawn_detached_update_helper(plan: &UpdatePlan) -> Result<()> {
    if let Some(ref staged_app) = plan.staged_app_bundle {
        if !staged_app.is_dir() {
            bail!(
                "Staged macOS app bundle missing: {}",
                staged_app.display()
            );
        }
    }
    if !plan.staged_exe.is_file() {
        bail!("Staged update binary missing: {}", plan.staged_exe.display());
    }
    ensure_target_dir_writable(&plan.target_dir)?;

    let current_exe = std::env::current_exe().context("Cannot resolve current executable")?;
    let temp_dir = std::env::temp_dir();
    let nonce = &uuid::Uuid::new_v4().simple().to_string()[..10];
    let helper_name = if cfg!(windows) {
        format!("bypax-updater-{}.exe", nonce)
    } else {
        format!("bypax-updater-{}", nonce)
    };
    let helper_exe = temp_dir.join(helper_name);
    let plan_path = temp_dir.join(format!("bypax-update-plan-{}.json", nonce));

    std::fs::copy(&current_exe, &helper_exe).context("Failed to copy updater helper binary")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&helper_exe, std::fs::Permissions::from_mode(0o755));
    }
    #[cfg(target_os = "macos")]
    {
        // Re-sign the copied standalone helper binary ad-hoc so Apple Silicon accepts it
        // even when the source binary carried bundle-bound CodeResources hashes.
        let _ = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&helper_exe)
            .stdin(std::process::Stdio::null())
            .output();
        let _ = std::process::Command::new("/usr/bin/xattr")
            .args(["-d", "com.apple.quarantine"])
            .arg(&helper_exe)
            .stdin(std::process::Stdio::null())
            .output();
    }
    std::fs::write(&plan_path, serde_json::to_string_pretty(plan)?)
        .context("Failed to persist update plan")?;

    let mut cmd = std::process::Command::new(&helper_exe);
    cmd.arg(APPLY_UPDATE_ARG)
        .arg(&plan_path)
        .current_dir(&temp_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
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

/// Computes a non-colliding sibling `.prev-<nonce>` backup path used when the canonical
/// `.prev` backup already exists and is locked by the OS (for example, a kernel-mapped
/// `WinDivert64.prev.sys` left over from a prior upgrade before reboot).
pub fn unique_backup_path_for(target: &Path) -> PathBuf {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let nonce = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let file_name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bypax.exe");
    if let Some(stem) = target.file_stem().and_then(|s| s.to_str()) {
        if let Some(ext) = target.extension().and_then(|s| s.to_str()) {
            parent.join(format!("{}.prev-{}.{}", stem, nonce, ext))
        } else {
            parent.join(format!("{}.prev-{}", stem, nonce))
        }
    } else {
        parent.join(format!("{}.prev-{}", file_name, nonce))
    }
}

fn sha256_file_bytes(path: &Path) -> Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Returns `true` when both paths are existing regular files with identical byte length
/// and SHA-256 digest. Used to avoid needlessly touching unchanged kernel drivers or
/// companion binaries during multi-binary upgrades.
pub fn files_are_identical(a: &Path, b: &Path) -> bool {
    let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::symlink_metadata(b)) else {
        return false;
    };
    if !ma.is_file() || !mb.file_type().is_file() || ma.len() != mb.len() {
        return false;
    }
    match (sha256_file_bytes(a), sha256_file_bytes(b)) {
        (Ok(ha), Ok(hb)) => ha == hb,
        _ => false,
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

/// Computes the hidden sibling `.prev.app` backup path for a macOS `.app` bundle so Finder and
/// Launchpad do not surface a duplicate icon during an in-place swap.
pub fn backup_app_bundle_path_for(target_app: &Path) -> PathBuf {
    let parent = target_app.parent().unwrap_or_else(|| Path::new("."));
    let stem = target_app
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Bypax");
    let ext = target_app
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("app");
    parent.join(format!(".{}.prev.{}", stem, ext))
}

#[cfg(not(target_os = "macos"))]
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&src_path)?;
        if meta.file_type().is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if meta.file_type().is_file() {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn copy_app_bundle_dir(src_app: &Path, dst_app: &Path) -> Result<()> {
    if dst_app.exists() {
        let _ = std::fs::remove_dir_all(dst_app);
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/ditto")
            .arg(src_app)
            .arg(dst_app)
            .stdin(std::process::Stdio::null())
            .output()
            .context("Failed to execute ditto while staging macOS app bundle")?;
        if !out.status.success() {
            let _ = std::fs::remove_dir_all(dst_app);
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("ditto failed to stage app bundle: {}", stderr.trim());
        }
        let _ = std::process::Command::new("/usr/bin/xattr")
            .args(["-dr", "com.apple.quarantine"])
            .arg(dst_app)
            .stdin(std::process::Stdio::null())
            .output();
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        copy_dir_recursive(src_app, dst_app)
    }
}

/// Atomically replaces a macOS `.app` bundle with a staged bundle via same-volume pre-staging,
/// hidden `.prev.app` backup, and automatic rollback on failure.
pub fn replace_macos_app_bundle_atomically(staged_app: &Path, target_app: &Path) -> Result<()> {
    replace_macos_app_bundle_atomically_internal(
        staged_app,
        target_app,
        DEFAULT_SWAP_MAX_ATTEMPTS,
        Duration::from_millis(DEFAULT_SWAP_RETRY_DELAY_MS),
        |_| Ok(()),
    )
}

fn replace_macos_app_bundle_atomically_internal<F>(
    staged_app: &Path,
    target_app: &Path,
    max_attempts: usize,
    retry_delay: Duration,
    mut before_swap_hook: F,
) -> Result<()>
where
    F: FnMut(&Path) -> Result<()>,
{
    if !staged_app.is_dir() {
        bail!("Staged app bundle missing: {}", staged_app.display());
    }
    if !staged_app.join("Contents").join("MacOS").join("bypax").is_file() {
        bail!(
            "Staged app bundle missing Contents/MacOS/bypax: {}",
            staged_app.display()
        );
    }
    let parent = target_app
        .parent()
        .ok_or_else(|| anyhow!("Target app bundle has no parent: {}", target_app.display()))?;
    std::fs::create_dir_all(parent)?;

    let sibling_tmp = sibling_tmp_path_for(target_app);
    let backup = backup_app_bundle_path_for(target_app);

    if sibling_tmp.exists() {
        let _ = std::fs::remove_dir_all(&sibling_tmp);
    }
    copy_app_bundle_dir(staged_app, &sibling_tmp)?;

    let attempts = max_attempts.max(1);
    let mut last_err = String::new();
    for attempt in 0..attempts {
        if let Err(e) = before_swap_hook(target_app) {
            let _ = std::fs::remove_dir_all(&sibling_tmp);
            return Err(e);
        }

        if backup.exists() {
            let _ = std::fs::remove_dir_all(&backup);
        }

        let existed_before = target_app.exists();
        if existed_before {
            if let Err(e) = std::fs::rename(target_app, &backup) {
                last_err = format!("rename existing app bundle to backup: {}", e);
                if attempt + 1 < attempts {
                    std::thread::sleep(retry_delay);
                }
                continue;
            }
        }

        match std::fs::rename(&sibling_tmp, target_app) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = format!("rename staged app bundle into place: {}", e);
                if existed_before {
                    let _ = std::fs::rename(&backup, target_app);
                }
                if attempt + 1 < attempts {
                    std::thread::sleep(retry_delay);
                }
            }
        }
    }

    let _ = std::fs::remove_dir_all(&sibling_tmp);
    Err(anyhow!(
        "Failed to replace {} after {} attempts: {}",
        target_app.display(),
        attempts,
        last_err
    ))
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
    let default_backup = backup_path_for(target);
    let mut last_err = String::new();
    let attempts = max_attempts.max(1);

    for attempt in 0..attempts {
        let mut backup = default_backup.clone();
        if backup.exists() {
            let _ = std::fs::remove_file(&backup);
            if backup.exists() {
                // Canonical `.prev` backup is still locked (e.g. a kernel-mapped `.sys` driver
                // image from a prior upgrade). Use a fresh sibling backup name instead of failing
                // with ACCESS_DENIED trying to overwrite the locked destination.
                backup = unique_backup_path_for(target);
            }
        }

        let existed_before = target.exists();
        if existed_before {
            if let Err(e) = std::fs::rename(target, &backup) {
                if backup.exists() {
                    let fallback = unique_backup_path_for(target);
                    if std::fs::rename(target, &fallback).is_ok() {
                        backup = fallback;
                    } else {
                        last_err = format!("rename old to backup: {}", e);
                        if attempt + 1 < attempts {
                            std::thread::sleep(retry_delay);
                        }
                        continue;
                    }
                } else {
                    last_err = format!("rename old to backup: {}", e);
                    if attempt + 1 < attempts {
                        std::thread::sleep(retry_delay);
                    }
                    continue;
                }
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
/// Skips staging and swapping cleanly when `target` already matches `staged` by SHA-256.
pub fn replace_binary_atomically(staged: &Path, target: &Path) -> Result<()> {
    if files_are_identical(staged, target) {
        return Ok(());
    }

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

    // Phase 1: pre-copy every changed staged file into its same-volume sibling `.new.tmp`
    // so read/disk errors abort cleanly before any live file is touched. Skip files that are
    // already byte-for-byte identical (e.g. unchanged WinDivert64.sys or sing-box.exe) so we
    // never provoke unnecessary kernel/AV file locks.
    let mut prepared: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(pairs.len());
    for (staged, target) in pairs {
        if !staged.is_file() {
            for (tmp, _) in &prepared {
                let _ = std::fs::remove_file(tmp);
            }
            bail!("Staged file missing: {}", staged.display());
        }
        if target.is_file() && files_are_identical(staged, target) {
            continue;
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
    if prepared.is_empty() {
        return Ok(());
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
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    runtime_dir: Option<PathBuf>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    target_app_bundle: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    last_pid: std::sync::Mutex<Option<u32>>,
}

impl OsServiceLifecycleController {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            runtime_dir: None,
            target_app_bundle: None,
            #[cfg(target_os = "macos")]
            last_pid: std::sync::Mutex::new(None),
        }
    }

    pub fn for_plan(service_name: impl Into<String>, plan: &UpdatePlan) -> Self {
        Self {
            service_name: service_name.into(),
            runtime_dir: plan.runtime_dir.clone(),
            target_app_bundle: plan.target_app_bundle.clone(),
            #[cfg(target_os = "macos")]
            last_pid: std::sync::Mutex::new(None),
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

#[cfg(target_os = "macos")]
fn plist_references_app_bundle(plist_path: &Path, target_app: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(plist_path) else {
        return false;
    };
    let check_candidate = |p: &Path| {
        let s = p.to_string_lossy();
        let escaped = s
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        raw.contains(&format!("{}/Contents/MacOS/bypax-service", escaped))
            || raw.contains(&format!("{}/Contents/MacOS/bypax-service", s))
    };
    if check_candidate(target_app) {
        return true;
    }
    if let Ok(canon) = std::fs::canonicalize(target_app) {
        return check_candidate(&canon);
    }
    false
}

#[cfg(target_os = "macos")]
fn send_macos_service_command_sync(
    command: bypax_ipc::ServiceCommand,
    runtime_dir: Option<&Path>,
    timeout: Duration,
) -> Result<bypax_ipc::ServiceResponse> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(bypax_ipc::UNIX_SVC_SOCKET_PATH)
        .context("Unable to connect to macOS bypax-service socket")?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let token = bypax_ipc::load_ipc_token(runtime_dir).unwrap_or_default();
    let env = bypax_ipc::ServiceEnvelope {
        id: format!("updater-{}", now_epoch_ms()),
        session_token: token,
        command,
    };
    let mut payload = serde_json::to_string(&env)?;
    payload.push('\n');
    stream.write_all(payload.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        bail!("macOS bypax-service closed socket before responding");
    }
    let resp: bypax_ipc::ServiceResponse = serde_json::from_str(line.trim())?;
    Ok(resp)
}

#[cfg(target_os = "macos")]
impl ServiceLifecycleController for OsServiceLifecycleController {
    fn is_service_running(&self) -> bool {
        let plist = Path::new(MACOS_LAUNCHD_PLIST_PATH);
        if !plist.is_file() || !Path::new(bypax_ipc::UNIX_SVC_SOCKET_PATH).exists() {
            return false;
        }
        if let Some(ref target_app) = self.target_app_bundle {
            if !plist_references_app_bundle(plist, target_app) {
                return false;
            }
        }
        match send_macos_service_command_sync(
            bypax_ipc::ServiceCommand::Ping,
            self.runtime_dir.as_deref(),
            Duration::from_millis(800),
        ) {
            Ok(resp) if resp.ok => {
                if let Ok(mut guard) = self.last_pid.lock() {
                    *guard = resp.service_pid;
                }
                true
            }
            _ => false,
        }
    }

    fn stop_service_gracefully(&self) -> Result<()> {
        let old_pid = self.last_pid.lock().ok().and_then(|g| *g);
        let _ = send_macos_service_command_sync(
            bypax_ipc::ServiceCommand::Shutdown,
            self.runtime_dir.as_deref(),
            Duration::from_secs(2),
        );
        if let Some(pid) = old_pid {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline && is_pid_alive_macos(pid) {
                std::thread::sleep(Duration::from_millis(100));
            }
        } else {
            std::thread::sleep(Duration::from_millis(300));
        }
        Ok(())
    }

    fn start_service(&self) -> Result<()> {
        // LaunchDaemon `com.bypax.service` runs with `KeepAlive=true` and `ThrottleInterval=2`,
        // so launchd automatically respawns the newly swapped binary after Shutdown.
        let old_pid = self.last_pid.lock().ok().and_then(|g| *g);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(resp) = send_macos_service_command_sync(
                bypax_ipc::ServiceCommand::Ping,
                self.runtime_dir.as_deref(),
                Duration::from_millis(600),
            ) {
                if resp.ok && (old_pid.is_none() || resp.service_pid != old_pid) {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
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

#[cfg(target_os = "macos")]
fn is_pid_alive_macos(pid: u32) -> bool {
    if pid <= 1 {
        return false;
    }
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    let exists = rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    if !exists {
        return false;
    }

    // Treat zombie processes (SZOMB / ps stat 'Z*') as already exited: all file descriptors,
    // sockets, and single-instance locks are already released even before reaping.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let filled = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast::<libc::c_void>(),
            size,
        )
    };
    if filled >= size {
        const SZOMB: u32 = 5;
        return info.pbi_status != SZOMB;
    }

    // `proc_pidinfo` returns 0 both for zombies and for cross-UID (root) processes;
    // disambiguate cleanly with `/bin/ps -o stat= -p <pid>`.
    if let Ok(out) = std::process::Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .stdin(std::process::Stdio::null())
        .output()
    {
        if !out.status.success() {
            return false;
        }
        let stat = String::from_utf8_lossy(&out.stdout);
        let trimmed = stat.trim();
        if trimmed.is_empty() || trimmed.starts_with('Z') {
            return false;
        }
    }
    true
}

#[cfg(target_os = "macos")]
fn wait_for_pid_exit(pid: u32, timeout_ms: u32) {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    while Instant::now() < deadline && is_pid_alive_macos(pid) {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(250));
}

#[cfg(not(any(windows, target_os = "macos")))]
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
    let args = build_relaunch_args(plan, helper_exe);

    #[cfg(target_os = "macos")]
    if let Some(ref app_bundle) = plan.target_app_bundle {
        if app_bundle.is_dir() {
            let mut open_cmd = std::process::Command::new("/usr/bin/open");
            open_cmd
                .arg("-n")
                .arg(app_bundle)
                .arg("--args")
                .args(&args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if let Ok(status) = open_cmd.status() {
                if status.success() {
                    return;
                }
            }
        }
    }

    let mut cmd = std::process::Command::new(&plan.target_exe);
    cmd.args(&args)
        .current_dir(&plan.target_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    let _ = cmd.spawn();
}

/// Collects the ordered list of changed `(staged_src, target_dst)` pairs for an `UpdatePlan`
/// (skipping targets whose installed content already matches the staged SHA-256 digest), plus a
/// flag indicating whether `BypaxService` must be stopped before replacing locked files.
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
        if files_are_identical(&staged, &target) {
            return;
        }
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

/// Core multi-binary / app-bundle update transaction with service coordination and atomic rollback.
/// Separated from process waiting/relaunch so integration tests can verify every edge case.
pub fn apply_update_transaction<S, F>(
    plan: &UpdatePlan,
    service_ctl: &S,
    max_attempts: usize,
    retry_delay: Duration,
    mut before_swap_hook: F,
) -> Result<()>
where
    S: ServiceLifecycleController,
    F: FnMut(usize, &Path) -> Result<()>,
{
    if let (Some(ref staged_app), Some(ref target_app)) =
        (&plan.staged_app_bundle, &plan.target_app_bundle)
    {
        // On macOS, swap the .app bundle atomically first (Unix rename does not fail on running
        // binaries), then bounce the LaunchDaemon so launchd respawns the newly installed binary.
        let daemon_running = service_ctl.is_service_running();
        replace_macos_app_bundle_atomically_internal(
            staged_app,
            target_app,
            max_attempts,
            retry_delay,
            |target| before_swap_hook(0, target),
        )?;
        if daemon_running {
            let _ = service_ctl.stop_service_gracefully();
            let _ = service_ctl.start_service();
        }
        return Ok(());
    }

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
    if let Some(helper_pid) = plan.helper_pid.filter(|&p| p > 0 && p != plan.parent_pid) {
        wait_for_pid_exit(helper_pid, 10_000);
    }

    let svc_name = plan
        .service_name
        .clone()
        .unwrap_or_else(|| BYPAX_SERVICE_NAME.to_string());
    let service_ctl = OsServiceLifecycleController::for_plan(svc_name, &plan);

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
            if name.contains(".prev.")
                || name.contains(".prev-")
                || name.ends_with(".prev")
                || name.ends_with(".new.tmp")
                || name.ends_with(".rollback.tmp")
            {
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
        if let Some(app_bundle) = find_macos_app_bundle_root(&exe) {
            let backup_bundle = backup_app_bundle_path_for(&app_bundle);
            if backup_bundle.is_dir() {
                let _ = std::fs::remove_dir_all(&backup_bundle);
            }
            let tmp_bundle = sibling_tmp_path_for(&app_bundle);
            if tmp_bundle.is_dir() {
                let _ = std::fs::remove_dir_all(&tmp_bundle);
            }
        }
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
        let report_portable = parse_app_release_json_for_platform(
            "0.1.0",
            json,
            "proxy:bypax",
            true,
            false,
            UpdatePlatform::WindowsX64,
            false,
        )
        .unwrap();
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
        assert!(report_portable.in_app_update_supported);

        // Non-portable with companion binaries also prefers portable bundle.
        let report_companions = parse_app_release_json_for_platform(
            "0.1.0",
            json,
            "direct",
            false,
            true,
            UpdatePlatform::WindowsX64,
            false,
        )
        .unwrap();
        assert_eq!(
            report_companions.selected_asset_kind.as_deref(),
            Some("portable_zip")
        );

        // Pure single-file standalone install selects lightweight standalone EXE.
        let report_standalone = parse_app_release_json_for_platform(
            "0.1.0",
            json,
            "direct",
            false,
            false,
            UpdatePlatform::WindowsX64,
            false,
        )
        .unwrap();
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
    fn parses_macos_release_assets_by_arch_and_bundle_writability() {
        let json = r#"{
            "tag_name": "v0.3.0",
            "name": "Bypax v0.3.0",
            "html_url": "https://github.com/Nexusyyan/bypax/releases/tag/v0.3.0",
            "assets": [
                {
                    "name": "bypax-v0.3.0-x86_64-windows-portable.zip",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.3.0/bypax-v0.3.0-x86_64-windows-portable.zip",
                    "size": 22000000
                },
                {
                    "name": "bypax-v0.3.0-aarch64-macos.dmg",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.3.0/bypax-v0.3.0-aarch64-macos.dmg",
                    "size": 19000000
                },
                {
                    "name": "bypax-v0.3.0-x86_64-macos.dmg",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.3.0/bypax-v0.3.0-x86_64-macos.dmg",
                    "size": 19500000
                },
                {
                    "name": "SHA256SUMS.txt",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.3.0/SHA256SUMS.txt",
                    "size": 320
                }
            ]
        }"#;

        let arm64 = parse_app_release_json_for_platform(
            "0.2.0",
            json,
            "direct",
            false,
            false,
            UpdatePlatform::MacosArm64,
            true,
        )
        .unwrap();
        assert!(arm64.update_available);
        assert_eq!(
            arm64.selected_asset_name.as_deref(),
            Some("bypax-v0.3.0-aarch64-macos.dmg")
        );
        assert_eq!(arm64.selected_asset_kind.as_deref(), Some("macos_dmg"));
        assert_eq!(arm64.install_mode, "app_bundle");
        assert!(arm64.in_app_update_supported);

        // Non-writable or translocated bundle disables in-app auto-replace cleanly.
        let arm64_ro = parse_app_release_json_for_platform(
            "0.2.0",
            json,
            "direct",
            false,
            false,
            UpdatePlatform::MacosArm64,
            false,
        )
        .unwrap();
        assert_eq!(
            arm64_ro.selected_asset_name.as_deref(),
            Some("bypax-v0.3.0-aarch64-macos.dmg")
        );
        assert!(!arm64_ro.in_app_update_supported);

        let x64 = parse_app_release_json_for_platform(
            "0.2.0",
            json,
            "proxy:bypax",
            false,
            false,
            UpdatePlatform::MacosX64,
            true,
        )
        .unwrap();
        assert_eq!(
            x64.selected_asset_name.as_deref(),
            Some("bypax-v0.3.0-x86_64-macos.dmg")
        );
        assert!(x64.in_app_update_supported);

        // Windows-only release must never select a Windows binary on macOS.
        let win_only = r#"{
            "tag_name": "v0.3.0",
            "assets": [
                {
                    "name": "bypax-v0.3.0-x86_64-windows.exe",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.3.0/bypax-v0.3.0-x86_64-windows.exe",
                    "size": 7000000
                },
                {
                    "name": "SHA256SUMS.txt",
                    "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.3.0/SHA256SUMS.txt",
                    "size": 128
                }
            ]
        }"#;
        let mac_missing = parse_app_release_json_for_platform(
            "0.2.0",
            win_only,
            "direct",
            false,
            false,
            UpdatePlatform::MacosArm64,
            true,
        )
        .unwrap();
        assert!(mac_missing.selected_asset_url.is_none());
        assert!(!mac_missing.in_app_update_supported);
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
            helper_pid: None,
            target_exe: install_dir.join("bypax.exe"),
            target_dir: install_dir.clone(),
            target_app_bundle: None,
            portable_mode: true,
            staged_dir: staged_dir.clone(),
            staged_exe: payload_dir.join("bypax.exe"),
            staged_app_bundle: None,
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
            runtime_dir: None,
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
            helper_pid: None,
            target_exe: install_dir.join("bypax.exe"),
            target_dir: install_dir.clone(),
            target_app_bundle: None,
            portable_mode: true,
            staged_dir: dir.path().join("stage"),
            staged_exe: payload_dir.join("bypax.exe"),
            staged_app_bundle: None,
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
            runtime_dir: None,
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

    fn write_fake_macho(path: &Path, size: usize, cputype: u32, marker: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut bytes = vec![0u8; size];
        bytes[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        bytes[4..8].copy_from_slice(&cputype.to_le_bytes());
        let end = (64 + marker.len()).min(size);
        bytes[64..end].copy_from_slice(&marker[..(end - 64)]);
        std::fs::write(path, &bytes).unwrap();
    }

    fn write_fake_universal_macho(path: &Path, size: usize, cpus: &[u32]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut bytes = vec![0u8; size];
        bytes[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        bytes[4..8].copy_from_slice(&(cpus.len() as u32).to_be_bytes());
        for (idx, cpu) in cpus.iter().enumerate() {
            let off = 8 + idx * 20;
            bytes[off..off + 4].copy_from_slice(&cpu.to_be_bytes());
        }
        std::fs::write(path, &bytes).unwrap();
    }

    fn build_fake_macos_bundle(root: &Path, cputype: u32, marker: &[u8]) {
        std::fs::create_dir_all(root.join("Contents/MacOS/core")).unwrap();
        std::fs::create_dir_all(root.join("Contents/Resources/skills/bypax-agent")).unwrap();
        std::fs::write(
            root.join("Contents/Info.plist"),
            b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>bypax</string></dict></plist>",
        )
        .unwrap();
        write_fake_macho(&root.join("Contents/MacOS/bypax"), 70_000, cputype, marker);
        write_fake_macho(
            &root.join("Contents/MacOS/bypax-cli"),
            70_000,
            cputype,
            marker,
        );
        write_fake_macho(
            &root.join("Contents/MacOS/bypax-service"),
            70_000,
            cputype,
            marker,
        );
        write_fake_macho(
            &root.join("Contents/MacOS/core/sing-box"),
            70_000,
            cputype,
            marker,
        );
        std::fs::write(
            root.join("Contents/Resources/skills/bypax-agent/SKILL.md"),
            marker,
        )
        .unwrap();
    }

    #[test]
    fn finds_macos_app_bundle_root_and_detects_translocation() {
        let app_exe = PathBuf::from("/Applications/Bypax.app/Contents/MacOS/bypax");
        assert_eq!(
            find_macos_app_bundle_root(&app_exe),
            Some(PathBuf::from("/Applications/Bypax.app"))
        );
        assert!(!is_macos_translocated_path(&app_exe));

        let dev_exe = PathBuf::from("/tmp/bypax/target/debug/bypax");
        assert_eq!(find_macos_app_bundle_root(&dev_exe), None);

        let translocated = PathBuf::from(
            "/private/var/folders/ab/cd/T/AppTranslocation/1234-5678/d/Bypax.app/Contents/MacOS/bypax",
        );
        assert!(is_macos_translocated_path(&translocated));
        assert!(!is_macos_app_bundle_updatable(&translocated));

        let dir = tempdir().unwrap();
        let writable_app = dir.path().join("Bypax.app");
        build_fake_macos_bundle(&writable_app, MACHO_CPU_TYPE_ARM64, b"v1");
        assert!(is_macos_app_bundle_updatable(
            &writable_app.join("Contents/MacOS/bypax")
        ));
    }

    #[test]
    fn validates_macho_single_and_universal_headers() {
        let dir = tempdir().unwrap();
        let bad = dir.path().join("not-macho");
        std::fs::write(&bad, vec![0u8; 70_000]).unwrap();
        assert!(validate_macho_binary(&bad, MIN_MACHO_BYTES, Some(MACHO_CPU_TYPE_ARM64)).is_err());

        let arm_bin = dir.path().join("bypax-arm64");
        write_fake_macho(&arm_bin, 70_000, MACHO_CPU_TYPE_ARM64, b"arm64");
        assert!(validate_macho_binary(&arm_bin, MIN_MACHO_BYTES, Some(MACHO_CPU_TYPE_ARM64)).is_ok());
        assert!(
            validate_macho_binary(&arm_bin, MIN_MACHO_BYTES, Some(MACHO_CPU_TYPE_X86_64)).is_err()
        );

        let fat_bin = dir.path().join("bypax-universal");
        write_fake_universal_macho(
            &fat_bin,
            70_000,
            &[MACHO_CPU_TYPE_X86_64, MACHO_CPU_TYPE_ARM64],
        );
        assert!(validate_macho_binary(&fat_bin, MIN_MACHO_BYTES, Some(MACHO_CPU_TYPE_ARM64)).is_ok());
        assert!(
            validate_macho_binary(&fat_bin, MIN_MACHO_BYTES, Some(MACHO_CPU_TYPE_X86_64)).is_ok()
        );
        assert!(validate_macho_binary(&fat_bin, MIN_MACHO_BYTES, Some(0x0100_0099)).is_err());
    }

    #[test]
    fn macos_app_bundle_atomic_swap_coordinates_daemon_and_rolls_back_on_failure() {
        let dir = tempdir().unwrap();
        let apps_dir = dir.path().join("Applications");
        let stage_dir = dir.path().join("stage");
        let target_app = apps_dir.join("Bypax.app");
        let staged_app = stage_dir.join("payload").join("Bypax.app");

        build_fake_macos_bundle(&target_app, MACHO_CPU_TYPE_ARM64, b"OLD_MAC_V1");
        build_fake_macos_bundle(&staged_app, MACHO_CPU_TYPE_ARM64, b"NEW_MAC_V2");

        validate_macos_app_bundle(&staged_app, Some(MACHO_CPU_TYPE_ARM64), false).unwrap();

        let staged_state = AppUpdateState {
            stage: AppUpdateStage::ReadyToRestart,
            target_version: Some("0.3.0".to_string()),
            target_tag: Some("v0.3.0".to_string()),
            asset_kind: Some("macos_dmg".to_string()),
            staged_dir: Some(stage_dir.to_string_lossy().to_string()),
            staged_exe_path: Some(
                staged_app
                    .join("Contents/MacOS/bypax")
                    .to_string_lossy()
                    .to_string(),
            ),
            staged_app_bundle_path: Some(staged_app.to_string_lossy().to_string()),
            ..AppUpdateState::default()
        };
        let plan = UpdatePlan::from_staged(
            &staged_state,
            0,
            target_app.join("Contents/MacOS/bypax"),
            apps_dir.clone(),
            false,
            stage_dir.clone(),
            staged_app.join("Contents/MacOS/bypax"),
            true,
            false,
            true,
            false,
            dir.path().join("runtime/last-update-result.json"),
        );
        assert_eq!(plan.target_app_bundle.as_deref(), Some(target_app.as_path()));
        assert_eq!(plan.staged_app_bundle.as_deref(), Some(staged_app.as_path()));

        // Injected failure before swap must keep OLD_MAC_V1 intact and leave daemon untouched.
        let mock_svc_fail = MockServiceController::new(true);
        let err = apply_update_transaction(
            &plan,
            &mock_svc_fail,
            2,
            Duration::from_millis(5),
            |_, _| bail!("simulated macOS bundle swap failure"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("simulated macOS bundle swap failure"));
        assert!(mock_svc_fail.recorded_events().is_empty());
        assert_eq!(
            &std::fs::read(target_app.join("Contents/MacOS/bypax")).unwrap()[64..74],
            b"OLD_MAC_V1"
        );
        assert!(!sibling_tmp_path_for(&target_app).exists());

        // Successful swap replaces entire bundle atomically and bounces running LaunchDaemon.
        let mock_svc_ok = MockServiceController::new(true);
        apply_update_transaction(&plan, &mock_svc_ok, 3, Duration::from_millis(5), |_, _| {
            Ok(())
        })
        .unwrap();
        assert_eq!(mock_svc_ok.recorded_events(), vec!["stop", "start"]);
        assert_eq!(
            &std::fs::read(target_app.join("Contents/MacOS/bypax")).unwrap()[64..74],
            b"NEW_MAC_V2"
        );
        assert_eq!(
            &std::fs::read(target_app.join("Contents/MacOS/bypax-service")).unwrap()[64..74],
            b"NEW_MAC_V2"
        );
        assert_eq!(
            std::fs::read(target_app.join("Contents/Resources/skills/bypax-agent/SKILL.md"))
                .unwrap(),
            b"NEW_MAC_V2"
        );
        let backup = backup_app_bundle_path_for(&target_app);
        assert!(backup.is_dir());
        assert_eq!(
            &std::fs::read(backup.join("Contents/MacOS/bypax")).unwrap()[64..74],
            b"OLD_MAC_V1"
        );
    }

    #[test]
    fn batch_swap_skips_byte_identical_driver_files_even_with_locked_prev_backup() {
        let dir = tempdir().unwrap();
        let install_dir = dir.path().join("install");
        let payload_dir = dir.path().join("payload");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::create_dir_all(&payload_dir).unwrap();

        write_fake_pe(&install_dir.join("bypax.exe"), 70_000, b"OLD_GUI");
        write_fake_pe(&payload_dir.join("bypax.exe"), 70_000, b"NEW_GUI");

        // Identical WinDivert driver files across versions (same bytes as installed).
        write_fake_pe(
            &install_dir.join("runtime/windivert/WinDivert64.sys"),
            20_000,
            b"SAME_WD_SYS",
        );
        write_fake_pe(
            &payload_dir.join("runtime/windivert/WinDivert64.sys"),
            20_000,
            b"SAME_WD_SYS",
        );

        // Simulate a stale kernel-locked WinDivert64.prev.sys left from an earlier upgrade.
        let locked_prev = install_dir.join("runtime/windivert/WinDivert64.prev.sys");
        write_fake_pe(&locked_prev, 20_000, b"STALE_LOCKED_PREV");
        #[cfg(windows)]
        let _lock_guard = {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&locked_prev)
                .unwrap()
        };

        let bundle = discover_staged_bundle_files(&payload_dir, true).unwrap();
        let plan = UpdatePlan {
            parent_pid: 0,
            helper_pid: None,
            target_exe: install_dir.join("bypax.exe"),
            target_dir: install_dir.clone(),
            target_app_bundle: None,
            portable_mode: true,
            staged_dir: dir.path().join("stage"),
            staged_exe: payload_dir.join("bypax.exe"),
            staged_app_bundle: None,
            staged_core_exe: bundle.core_exe,
            staged_cli_exe: bundle.cli_exe,
            staged_service_exe: bundle.service_exe,
            extra_swaps: bundle.extra_swaps,
            docs_to_copy: vec![],
            resume_core: true,
            resume_sys_proxy: true,
            resume_app_proxy: true,
            resume_tun: false,
            service_name: Some(BYPAX_SERVICE_NAME.to_string()),
            runtime_dir: None,
            from_version: "0.1.4".to_string(),
            to_version: "0.1.5".to_string(),
            to_tag: "v0.1.5".to_string(),
            result_file: install_dir.join("result.json"),
        };

        let mock_svc = MockServiceController::new(false);
        let mut swapped_names: Vec<String> = Vec::new();
        apply_update_transaction(&plan, &mock_svc, 3, Duration::from_millis(5), |_, dst| {
            if let Some(name) = dst.file_name().and_then(|s| s.to_str()) {
                swapped_names.push(name.to_string());
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(swapped_names, vec!["bypax.exe".to_string()]);
        assert_eq!(
            &std::fs::read(install_dir.join("bypax.exe")).unwrap()[160..167],
            b"NEW_GUI"
        );
        assert_eq!(
            &std::fs::read(install_dir.join("runtime/windivert/WinDivert64.sys")).unwrap()
                [160..171],
            b"SAME_WD_SYS"
        );
    }

    #[test]
    fn swap_falls_back_to_unique_backup_when_prev_is_locked_and_supports_rollback_and_cleanup() {
        let dir = tempdir().unwrap();
        let windivert_dir = dir.path().join("install/runtime/windivert");
        let payload_dir = dir.path().join("payload");
        std::fs::create_dir_all(&windivert_dir).unwrap();
        std::fs::create_dir_all(&payload_dir).unwrap();

        let target_sys = windivert_dir.join("WinDivert64.sys");
        let locked_prev = windivert_dir.join("WinDivert64.prev.sys");
        let staged_sys = payload_dir.join("WinDivert64.sys");
        let target_extra = dir.path().join("install/bypax.exe");
        let staged_extra = payload_dir.join("bypax.exe");

        write_fake_pe(&target_sys, 20_000, b"OLD_WD_SYS");
        write_fake_pe(&locked_prev, 20_000, b"KERNEL_LOCKED_PREV");
        write_fake_pe(&staged_sys, 20_000, b"NEW_WD_SYS");
        write_fake_pe(&target_extra, 70_000, b"OLD_GUI");
        write_fake_pe(&staged_extra, 70_000, b"NEW_GUI");

        // Lock `WinDivert64.prev.sys` so deleting or overwriting it fails with sharing/access error.
        #[cfg(windows)]
        let lock_guard = {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&locked_prev)
                .unwrap()
        };

        // Case 1: Rollback restores OLD_WD_SYS even when a unique fallback backup was used.
        let rollback_err = replace_batch_atomically_internal(
            &[
                (staged_sys.clone(), target_sys.clone()),
                (staged_extra.clone(), target_extra.clone()),
            ],
            2,
            Duration::from_millis(5),
            |_, dst| {
                if dst.file_name().and_then(|s| s.to_str()) == Some("bypax.exe") {
                    bail!("injected failure after WinDivert64.sys swapped");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(rollback_err.to_string().contains("injected failure"));
        assert_eq!(&std::fs::read(&target_sys).unwrap()[160..170], b"OLD_WD_SYS");
        assert_eq!(&std::fs::read(&target_extra).unwrap()[160..167], b"OLD_GUI");

        // Case 2: Successful swap when WinDivert64.sys actually changed while `.prev.sys` is locked.
        replace_batch_atomically_internal(
            &[
                (staged_sys.clone(), target_sys.clone()),
                (staged_extra.clone(), target_extra.clone()),
            ],
            2,
            Duration::from_millis(5),
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(&std::fs::read(&target_sys).unwrap()[160..170], b"NEW_WD_SYS");
        assert_eq!(&std::fs::read(&target_extra).unwrap()[160..167], b"NEW_GUI");

        #[cfg(windows)]
        {
            // Verify fallback `.prev-<nonce>.sys` was created alongside the still-locked `.prev.sys`.
            let has_unique_backup = std::fs::read_dir(&windivert_dir)
                .unwrap()
                .flatten()
                .any(|e| {
                    e.file_name()
                        .to_str()
                        .map(|n| n.starts_with("WinDivert64.prev-") && n.ends_with(".sys"))
                        .unwrap_or(false)
                });
            assert!(has_unique_backup);
            drop(lock_guard);
        }

        // Once unlocked, cleanup removes both `.prev.` and `.prev-` artifacts cleanly.
        cleanup_prev_backups_in_dir(&windivert_dir);
        let remaining: Vec<String> = std::fs::read_dir(&windivert_dir)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert_eq!(remaining, vec!["WinDivert64.sys".to_string()]);
    }

    #[test]
    fn skips_identical_sha256_files_including_locked_windivert_driver_without_touching_target() {
        let dir = tempdir().unwrap();
        let install_dir = dir.path().join("install");
        let payload_dir = dir.path().join("payload");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::create_dir_all(&payload_dir).unwrap();

        // Changed binaries that must be swapped.
        write_fake_pe(&install_dir.join("bypax.exe"), 70_000, b"OLD_GUI");
        write_fake_pe(&install_dir.join("bypax-cli.exe"), 70_000, b"OLD_CLI");
        write_fake_pe(&install_dir.join("bypax-service.exe"), 70_000, b"OLD_SVC");
        write_fake_pe(&payload_dir.join("bypax.exe"), 70_000, b"NEW_GUI");
        write_fake_pe(&payload_dir.join("bypax-cli.exe"), 70_000, b"NEW_CLI");
        write_fake_pe(&payload_dir.join("bypax-service.exe"), 70_000, b"NEW_SVC");

        // Unchanged binaries and kernel driver with byte-for-byte identical contents.
        write_fake_pe(
            &install_dir.join("core/sing-box.exe"),
            70_000,
            b"SAME_CORE_1144",
        );
        write_fake_pe(
            &payload_dir.join("core/sing-box.exe"),
            70_000,
            b"SAME_CORE_1144",
        );
        write_fake_pe(
            &install_dir.join("runtime/windivert/WinDivert.dll"),
            20_000,
            b"SAME_WD_DLL",
        );
        write_fake_pe(
            &payload_dir.join("runtime/windivert/WinDivert.dll"),
            20_000,
            b"SAME_WD_DLL",
        );
        write_fake_pe(
            &install_dir.join("runtime/windivert/WinDivert64.sys"),
            20_000,
            b"SAME_WD_SYS",
        );
        write_fake_pe(
            &payload_dir.join("runtime/windivert/WinDivert64.sys"),
            20_000,
            b"SAME_WD_SYS",
        );

        // One identical doc (must be skipped) and one changed doc (must be swapped).
        std::fs::write(install_dir.join("LICENSE"), b"same-license-text").unwrap();
        std::fs::write(payload_dir.join("LICENSE"), b"same-license-text").unwrap();
        std::fs::write(install_dir.join("README.md"), b"old-readme").unwrap();
        std::fs::write(payload_dir.join("README.md"), b"new-readme-v2").unwrap();

        let bundle = discover_staged_bundle_files(&payload_dir, true).unwrap();
        let plan = UpdatePlan {
            parent_pid: 0,
            helper_pid: None,
            target_exe: install_dir.join("bypax.exe"),
            target_dir: install_dir.clone(),
            target_app_bundle: None,
            portable_mode: true,
            staged_dir: dir.path().join("stage"),
            staged_exe: payload_dir.join("bypax.exe"),
            staged_app_bundle: None,
            staged_core_exe: bundle.core_exe,
            staged_cli_exe: bundle.cli_exe,
            staged_service_exe: bundle.service_exe,
            extra_swaps: bundle.extra_swaps,
            docs_to_copy: vec!["LICENSE".to_string(), "README.md".to_string()],
            resume_core: true,
            resume_sys_proxy: false,
            resume_app_proxy: true,
            resume_tun: false,
            service_name: Some(BYPAX_SERVICE_NAME.to_string()),
            runtime_dir: None,
            from_version: "0.1.4".to_string(),
            to_version: "0.1.5".to_string(),
            to_tag: "v0.1.5".to_string(),
            result_file: install_dir.join("result.json"),
        };

        let mock_svc = MockServiceController::new(true);
        let mut swapped_targets: Vec<PathBuf> = Vec::new();
        apply_update_transaction(&plan, &mock_svc, 2, Duration::from_millis(5), |_, dst| {
            let name = dst.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.eq_ignore_ascii_case("WinDivert64.sys")
                || name.eq_ignore_ascii_case("WinDivert.dll")
                || name.eq_ignore_ascii_case("sing-box.exe")
                || name.eq_ignore_ascii_case("LICENSE")
            {
                bail!("unexpected swap attempt on identical file {}", dst.display());
            }
            swapped_targets.push(dst.to_path_buf());
            Ok(())
        })
        .unwrap();

        // Service was still coordinated because bypax-service.exe changed.
        assert_eq!(mock_svc.recorded_events(), vec!["stop", "start"]);
        assert!(mock_svc.is_service_running());

        // All changed files swapped cleanly.
        assert_eq!(
            &std::fs::read(install_dir.join("bypax.exe")).unwrap()[160..167],
            b"NEW_GUI"
        );
        assert_eq!(
            &std::fs::read(install_dir.join("bypax-cli.exe")).unwrap()[160..167],
            b"NEW_CLI"
        );
        assert_eq!(
            &std::fs::read(install_dir.join("bypax-service.exe")).unwrap()[160..167],
            b"NEW_SVC"
        );
        assert_eq!(
            std::fs::read(install_dir.join("README.md")).unwrap(),
            b"new-readme-v2"
        );
        assert_eq!(swapped_targets.len(), 4);

        // Unchanged kernel driver, DLL, core, and doc remained untouched with zero .prev/.tmp leftovers.
        let wd_sys = install_dir.join("runtime/windivert/WinDivert64.sys");
        let wd_dll = install_dir.join("runtime/windivert/WinDivert.dll");
        let core_exe = install_dir.join("core/sing-box.exe");
        let license = install_dir.join("LICENSE");
        assert_eq!(&std::fs::read(&wd_sys).unwrap()[160..171], b"SAME_WD_SYS");
        assert_eq!(&std::fs::read(&wd_dll).unwrap()[160..171], b"SAME_WD_DLL");
        assert_eq!(
            &std::fs::read(&core_exe).unwrap()[160..174],
            b"SAME_CORE_1144"
        );
        assert_eq!(std::fs::read(&license).unwrap(), b"same-license-text");
        for skipped in [&wd_sys, &wd_dll, &core_exe, &license] {
            assert!(
                !backup_path_for(skipped).exists(),
                "unexpected .prev backup created for identical file {}",
                skipped.display()
            );
            assert!(
                !sibling_tmp_path_for(skipped).exists(),
                "unexpected .tmp file created for identical file {}",
                skipped.display()
            );
        }

        // Direct replace_batch_atomically_internal also skips identical files cleanly.
        let direct_pairs = vec![
            (payload_dir.join("runtime/windivert/WinDivert64.sys"), wd_sys.clone()),
            (payload_dir.join("LICENSE"), license.clone()),
        ];
        replace_batch_atomically_internal(&direct_pairs, 2, Duration::from_millis(5), |_, dst| {
            bail!("hook must not be called for identical file {}", dst.display());
        })
        .unwrap();

        // Direct replace_binary_atomically on an identical target leaves zero backup/tmp artifacts.
        replace_binary_atomically(&payload_dir.join("runtime/windivert/WinDivert64.sys"), &wd_sys)
            .unwrap();
        assert!(!backup_path_for(&wd_sys).exists());
        assert!(!sibling_tmp_path_for(&wd_sys).exists());

        // When only non-service files differ, service stop/start is skipped as well.
        write_fake_pe(&payload_dir.join("bypax.exe"), 70_000, b"NEW_GUI_V2");
        let mock_svc_idle = MockServiceController::new(true);
        apply_update_transaction(
            &plan,
            &mock_svc_idle,
            2,
            Duration::from_millis(5),
            |_, dst| {
                let name = dst.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if name.eq_ignore_ascii_case("WinDivert64.sys") {
                    bail!("unexpected swap attempt on identical WinDivert64.sys");
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(mock_svc_idle.recorded_events().is_empty());
        assert_eq!(
            &std::fs::read(install_dir.join("bypax.exe")).unwrap()[160..170],
            b"NEW_GUI_V2"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn extracts_and_verifies_real_signed_macos_dmg_end_to_end() {
        let dir = tempdir().unwrap();
        let src_stage = dir.path().join("dmg-src");
        let src_app = src_stage.join("Bypax.app");
        std::fs::create_dir_all(src_app.join("Contents/MacOS")).unwrap();
        std::fs::write(
            src_app.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>bypax</string>
  <key>CFBundleIdentifier</key>
  <string>com.bypax.desktop.test</string>
  <key>CFBundleName</key>
  <string>Bypax</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleVersion</key>
  <string>0.3.0</string>
</dict>
</plist>
"#,
        )
        .unwrap();

        // Reuse the live test runner executable as a real host-architecture Mach-O binary.
        let host_exe = std::env::current_exe().unwrap();
        let bundled_exe = src_app.join("Contents/MacOS/bypax");
        std::fs::copy(&host_exe, &bundled_exe).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bundled_exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let sign_status = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--deep", "--sign", "-"])
            .arg(&src_app)
            .status()
            .unwrap();
        assert!(sign_status.success(), "ad-hoc codesign failed");

        let dmg_path = dir.path().join("bypax-v0.3.0-test-macos.dmg");
        let create_status = std::process::Command::new("/usr/bin/hdiutil")
            .args(["create", "-volname", "Bypax Test", "-srcfolder"])
            .arg(&src_stage)
            .args(["-ov", "-format", "UDZO"])
            .arg(&dmg_path)
            .status()
            .unwrap();
        assert!(create_status.success(), "hdiutil create failed");

        let payload_dir = dir.path().join("payload");
        let extracted = extract_macos_dmg_app(&dmg_path, &payload_dir).unwrap();
        assert_eq!(extracted, payload_dir.join("Bypax.app"));
        assert!(extracted.join("Contents/MacOS/bypax").is_file());
        assert!(extracted.join("Contents/Info.plist").is_file());
    }
}
