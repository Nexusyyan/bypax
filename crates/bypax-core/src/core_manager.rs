use crate::updater::{
    build_proxy_channels, compare_versions, replace_binary_atomically, ProxyChannel,
};
use anyhow::{anyhow, bail, Context, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub const PINNED_CORE_VERSION: &str = "v1.14.4";
pub const PINNED_WIN_AMD64_ZIP_SHA256: &str =
    "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df";
pub const PINNED_WIN_AMD64_EXE_SHA256: &str =
    "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9";

const SINGBOX_LATEST_API: &str = "https://api.github.com/repos/SagerNet/sing-box/releases/latest";
const SINGBOX_ALLOWED_PREFIX: &str = "https://github.com/SagerNet/sing-box/releases/download/";
const PROGRESS_EMIT_MS: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfficialReleaseInfo {
    pub tag_name: String,
    pub asset_name: String,
    pub download_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_size: Option<u64>,
    #[serde(default)]
    pub checked_via: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreUpdateCheckReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    pub latest_version: String,
    pub latest_tag: String,
    pub update_available: bool,
    pub asset_name: String,
    pub download_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_size: Option<u64>,
    pub checked_via: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreDownloadProgressEvent {
    pub phase: String,
    pub downloaded_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
}

pub struct CoreManager {
    core_dir: PathBuf,
}

impl CoreManager {
    pub fn new(core_dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&core_dir);
        Self { core_dir }
    }

    pub fn binary_path(&self) -> PathBuf {
        self.core_dir.join(core_binary_name())
    }

    pub fn backup_binary_path(&self) -> PathBuf {
        let dest = self.binary_path();
        if let (Some(parent), Some(stem), Some(ext)) = (
            dest.parent(),
            dest.file_stem().and_then(|s| s.to_str()),
            dest.extension().and_then(|s| s.to_str()),
        ) {
            parent.join(format!("{}.prev.{}", stem, ext))
        } else {
            self.core_dir.join(format!("{}.prev", core_binary_name()))
        }
    }

    /// Resolves an existing sing-box binary across managed data dir, executable sibling dir,
    /// and system PATH so users who already own sing-box work out of the box.
    pub fn resolve_binary_path(&self) -> Option<PathBuf> {
        let managed = self.binary_path();
        if managed.exists() {
            return Some(managed);
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                for cand in [
                    dir.join(core_binary_name()),
                    dir.join("core").join(core_binary_name()),
                ] {
                    if cand.exists() {
                        return Some(cand);
                    }
                }
            }
        }
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let cand = dir.join(core_binary_name());
                if cand.exists() {
                    return Some(cand);
                }
            }
        }
        None
    }

    pub fn is_installed(&self) -> bool {
        self.resolve_binary_path().is_some()
    }

    pub fn sha256_of_binary(&self) -> Result<Option<String>> {
        let Some(path) = self.resolve_binary_path() else {
            return Ok(None);
        };
        Ok(Some(compute_file_sha256(&path)?))
    }

    pub fn detect_version(&self) -> Option<String> {
        let path = self.resolve_binary_path()?;
        detect_version_at(&path)
    }

    /// Copies and validates a user-supplied official sing-box binary into a staging file
    /// WITHOUT touching the active binary yet, so an invalid file never breaks a working core.
    pub fn stage_local_binary(
        &self,
        source: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<(PathBuf, String)> {
        if !source.exists() {
            return Err(anyhow!("Source binary does not exist: {}", source.display()));
        }
        let digest = compute_file_sha256(source)?;
        if let Some(expected) = expected_sha256 {
            if !digest.eq_ignore_ascii_case(expected.trim()) {
                return Err(anyhow!(
                    "SHA-256 mismatch: expected {}, got {}",
                    expected,
                    digest
                ));
            }
        }
        std::fs::create_dir_all(&self.core_dir)?;
        let candidate = self.candidate_path();
        let _ = std::fs::remove_file(&candidate);
        std::fs::copy(source, &candidate)?;
        ensure_executable_bit(&candidate)?;

        let Some(ver) = detect_version_at(&candidate) else {
            let _ = std::fs::remove_file(&candidate);
            bail!("Selected file failed `sing-box version` verification");
        };
        Ok((candidate, ver))
    }

    /// Commits a verified candidate binary into the managed core path atomically, creating a
    /// `.prev` backup that can be restored via `rollback_binary` if startup fails.
    pub fn commit_staged_binary(&self, staged_candidate: &Path) -> Result<(String, String)> {
        std::fs::create_dir_all(&self.core_dir)?;
        let dest = self.binary_path();
        replace_binary_atomically(staged_candidate, &dest)?;
        let _ = std::fs::remove_file(staged_candidate);
        ensure_executable_bit(&dest)?;

        let version = detect_version_at(&dest)
            .ok_or_else(|| anyhow!("Installed binary failed `sing-box version` check"))?;
        let sha = compute_file_sha256(&dest)?;
        Ok((version, sha))
    }

    /// Restores the `.prev` backup binary if a newly committed core fails preflight/startup.
    pub fn rollback_binary(&self) -> Result<bool> {
        let backup = self.backup_binary_path();
        let dest = self.binary_path();
        if !backup.is_file() {
            return Ok(false);
        }
        if dest.exists() {
            let _ = std::fs::remove_file(&dest);
        }
        std::fs::rename(&backup, &dest)?;
        Ok(true)
    }

    /// Convenience single-step import (validates candidate BEFORE swapping existing binary).
    pub fn import_local_binary(
        &self,
        source: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<String> {
        let (candidate, _ver) = self.stage_local_binary(source, expected_sha256)?;
        let (ver, _sha) = self.commit_staged_binary(&candidate)?;
        Ok(ver)
    }

    /// Queries the official SagerNet/sing-box GitHub Releases API via active proxy -> system proxy -> direct.
    pub async fn fetch_latest_official_release(
        &self,
        local_proxy_port: Option<u16>,
    ) -> Result<OfficialReleaseInfo> {
        let channels = build_proxy_channels(local_proxy_port);
        let needle = target_asset_suffix();
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
                .get(SINGBOX_LATEST_API)
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    last_err = format!("{}: HTTP {}", ch.label(), r.status().as_u16());
                    continue;
                }
                Err(e) => {
                    last_err = format!("{}: {}", ch.label(), e);
                    continue;
                }
            };

            let val: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    last_err = format!("{}: {}", ch.label(), e);
                    continue;
                }
            };

            let tag = val["tag_name"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing tag_name"))?
                .to_string();
            let assets = val["assets"]
                .as_array()
                .ok_or_else(|| anyhow!("Missing assets"))?;
            for asset in assets {
                let name = asset["name"].as_str().unwrap_or_default();
                if name.ends_with(needle)
                    && !name.contains("legacy")
                    && !name.contains("musl")
                    && !name.contains("fips")
                {
                    let url = asset["browser_download_url"]
                        .as_str()
                        .ok_or_else(|| anyhow!("Missing download URL"))?
                        .to_string();
                    if !url.starts_with(SINGBOX_ALLOWED_PREFIX) {
                        continue;
                    }
                    let size = asset["size"].as_u64().filter(|s| *s > 0);
                    return Ok(OfficialReleaseInfo {
                        tag_name: tag,
                        asset_name: name.to_string(),
                        download_url: url,
                        asset_size: size,
                        checked_via: ch.label().to_string(),
                    });
                }
            }
            return Err(anyhow!("No matching official release asset for {}", needle));
        }

        Err(anyhow!(
            "Unable to query SagerNet/sing-box latest release ({})",
            last_err
        ))
    }

    /// Checks whether a newer official `sing-box` release is available compared to the installed binary.
    pub async fn check_for_core_update(
        &self,
        local_proxy_port: Option<u16>,
    ) -> Result<CoreUpdateCheckReport> {
        let installed_version = self.detect_version();
        let latest = self.fetch_latest_official_release(local_proxy_port).await?;
        let latest_version = latest.tag_name.trim_start_matches(['v', 'V']).to_string();
        let update_available = match installed_version.as_deref() {
            Some(cur) => compare_versions(&latest_version, cur) == Ordering::Greater,
            None => true,
        };
        Ok(CoreUpdateCheckReport {
            installed_version,
            latest_version,
            latest_tag: latest.tag_name,
            update_available,
            asset_name: latest.asset_name,
            download_url: latest.download_url,
            asset_size: latest.asset_size,
            checked_via: latest.checked_via,
        })
    }

    /// Downloads, verifies, extracts, and validates a candidate official `sing-box` binary
    /// while leaving any currently running core untouched until the caller commits the swap.
    pub async fn stage_official_core<F>(
        &self,
        local_proxy_port: Option<u16>,
        expected_sha256: Option<&str>,
        on_progress: F,
    ) -> Result<(PathBuf, String, String)>
    where
        F: Fn(CoreDownloadProgressEvent) + Send + Sync,
    {
        on_progress(CoreDownloadProgressEvent {
            phase: "checking".to_string(),
            downloaded_bytes: 0,
            total_bytes: None,
            percent: None,
            via: None,
            target_version: None,
        });

        // Try discovering the latest official SagerNet/sing-box release via proxy/system/direct.
        // On Windows x64, fall back gracefully to the SHA-256-pinned v1.14.4 release if GitHub API is unreachable.
        let (tag_name, asset_name, official_url, expected_size, pinned_zip_sha, pinned_exe_sha) =
            match self.fetch_latest_official_release(local_proxy_port).await {
                Ok(info) => {
                    let is_pinned_win = cfg!(all(target_os = "windows", target_arch = "x86_64"))
                        && info.tag_name.eq_ignore_ascii_case(PINNED_CORE_VERSION);
                    let zip_sha = expected_sha256.or(if is_pinned_win {
                        Some(PINNED_WIN_AMD64_ZIP_SHA256)
                    } else {
                        None
                    });
                    let exe_sha = if is_pinned_win {
                        Some(PINNED_WIN_AMD64_EXE_SHA256)
                    } else {
                        None
                    };
                    (
                        info.tag_name,
                        info.asset_name,
                        info.download_url,
                        info.asset_size,
                        zip_sha,
                        exe_sha,
                    )
                }
                Err(api_err) => {
                    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
                        let ver_num = PINNED_CORE_VERSION.trim_start_matches('v');
                        let asset = format!("sing-box-{}-windows-amd64.zip", ver_num);
                        let url = format!(
                            "https://github.com/SagerNet/sing-box/releases/download/{}/{}",
                            PINNED_CORE_VERSION, asset
                        );
                        (
                            PINNED_CORE_VERSION.to_string(),
                            asset,
                            url,
                            None,
                            Some(expected_sha256.unwrap_or(PINNED_WIN_AMD64_ZIP_SHA256)),
                            Some(PINNED_WIN_AMD64_EXE_SHA256),
                        )
                    } else {
                        return Err(api_err);
                    }
                }
            };

        // Build download attempts: official GitHub via proxy -> system proxy -> direct.
        // Only permit third-party mirrors when we have a mandatory SHA-256 hash to verify!
        let mut attempts: Vec<(String, ProxyChannel, String)> = Vec::new();
        for ch in build_proxy_channels(local_proxy_port) {
            attempts.push((official_url.clone(), ch.clone(), ch.label().to_string()));
        }
        if pinned_zip_sha.is_some() {
            attempts.push((
                format!("https://ghfast.top/{}", official_url),
                ProxyChannel::Direct,
                "mirror:ghfast".to_string(),
            ));
            attempts.push((
                format!("https://gh-proxy.com/{}", official_url),
                ProxyChannel::Direct,
                "mirror:gh-proxy".to_string(),
            ));
        }

        let mut downloaded_bytes: Option<Vec<u8>> = None;
        let mut used_via = String::new();
        let mut last_err = String::new();

        for (url, ch, via_label) in &attempts {
            let client = match ch.build_client(10, 120) {
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

            let total_len = resp.content_length().or(expected_size);
            on_progress(CoreDownloadProgressEvent {
                phase: "downloading".to_string(),
                downloaded_bytes: 0,
                total_bytes: total_len,
                percent: Some(0),
                via: Some(via_label.clone()),
                target_version: Some(tag_name.clone()),
            });

            let mut buf: Vec<u8> = match total_len {
                Some(n) if n <= 128 * 1024 * 1024 => Vec::with_capacity(n as usize),
                _ => Vec::new(),
            };
            let mut stream = resp.bytes_stream();
            let mut last_emit = Instant::now();
            let mut ok = true;

            while let Some(chunk_res) = stream.next().await {
                match chunk_res {
                    Ok(chunk) => {
                        buf.extend_from_slice(&chunk);
                        if last_emit.elapsed() >= Duration::from_millis(PROGRESS_EMIT_MS) {
                            let done = buf.len() as u64;
                            let pct = total_len
                                .filter(|t| *t > 0)
                                .map(|t| ((done.saturating_mul(100)) / t).min(99) as u8);
                            on_progress(CoreDownloadProgressEvent {
                                phase: "downloading".to_string(),
                                downloaded_bytes: done,
                                total_bytes: total_len,
                                percent: pct,
                                via: Some(via_label.clone()),
                                target_version: Some(tag_name.clone()),
                            });
                            last_emit = Instant::now();
                        }
                    }
                    Err(e) => {
                        last_err = format!("{}: {}", via_label, e);
                        ok = false;
                        break;
                    }
                }
            }

            if !ok || buf.is_empty() {
                continue;
            }

            on_progress(CoreDownloadProgressEvent {
                phase: "verifying".to_string(),
                downloaded_bytes: buf.len() as u64,
                total_bytes: Some(buf.len() as u64),
                percent: Some(100),
                via: Some(via_label.clone()),
                target_version: Some(tag_name.clone()),
            });

            if let Some(expected) = pinned_zip_sha {
                let got = hex::encode(Sha256::digest(&buf));
                if !got.eq_ignore_ascii_case(expected.trim()) {
                    last_err = format!(
                        "SHA-256 mismatch from {} (expected {}, got {})",
                        via_label, expected, got
                    );
                    continue;
                }
            }

            downloaded_bytes = Some(buf);
            used_via = via_label.clone();
            break;
        }

        let bytes = downloaded_bytes.ok_or_else(|| {
            anyhow!(
                "Unable to download official sing-box {} from GitHub or mirrors ({}). Use the Portable With-Core bundle or import a local sing-box binary.",
                tag_name,
                last_err
            )
        })?;

        on_progress(CoreDownloadProgressEvent {
            phase: "extracting".to_string(),
            downloaded_bytes: bytes.len() as u64,
            total_bytes: Some(bytes.len() as u64),
            percent: Some(100),
            via: Some(used_via.clone()),
            target_version: Some(tag_name.clone()),
        });

        let binary_bytes = extract_singbox_binary_from_archive(&asset_name, &bytes)?;

        if let Some(expected_exe) = pinned_exe_sha {
            let got_exe = hex::encode(Sha256::digest(&binary_bytes));
            if !got_exe.eq_ignore_ascii_case(expected_exe) {
                bail!(
                    "Extracted binary SHA-256 mismatch: expected {}, got {}",
                    expected_exe,
                    got_exe
                );
            }
        }

        std::fs::create_dir_all(&self.core_dir)?;
        let candidate = self.candidate_path();
        let _ = std::fs::remove_file(&candidate);
        std::fs::write(&candidate, &binary_bytes)?;
        ensure_executable_bit(&candidate)?;

        let detected_ver = detect_version_at(&candidate).ok_or_else(|| {
            let _ = std::fs::remove_file(&candidate);
            anyhow!("Extracted sing-box binary failed `sing-box version` verification")
        })?;

        Ok((candidate, detected_ver, used_via))
    }

    /// Backward-compatible single-step download & install helper.
    pub async fn download_official_core(&self, expected_sha256: Option<&str>) -> Result<(String, String)> {
        let (candidate, _ver, _via) = self
            .stage_official_core(None, expected_sha256, |_| {})
            .await?;
        self.commit_staged_binary(&candidate)
    }

    fn candidate_path(&self) -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            self.core_dir.join("sing-box.candidate.exe")
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.core_dir.join("sing-box.candidate")
        }
    }
}

fn extract_singbox_binary_from_archive(asset_name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    if asset_name.ends_with(".zip") {
        let reader = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader).context("Invalid ZIP archive")?;
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            if file.is_symlink() {
                continue;
            }
            let Some(enclosed) = file.enclosed_name().map(|p| p.to_path_buf()) else {
                continue;
            };
            let fname = enclosed
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if fname.eq_ignore_ascii_case("sing-box.exe") || fname == "sing-box" {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                if !buf.is_empty() {
                    return Ok(buf);
                }
            }
        }
        bail!("sing-box binary not found inside ZIP archive")
    } else if asset_name.ends_with(".tar.gz") || asset_name.ends_with(".tgz") {
        extract_singbox_from_targz(bytes)
    } else {
        bail!("Unsupported sing-box archive format: {}", asset_name)
    }
}

#[cfg(not(windows))]
fn extract_singbox_from_targz(bytes: &[u8]) -> Result<Vec<u8>> {
    let tmp_path = std::env::temp_dir().join(format!(
        "bypax-core-{}.tar.gz",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::write(&tmp_path, bytes)?;

    let result = (|| -> Result<Vec<u8>> {
        let list_out = Command::new("tar")
            .arg("-tzf")
            .arg(&tmp_path)
            .output()
            .context("Failed to execute tar to inspect archive")?;
        if !list_out.status.success() {
            bail!("tar -tzf failed: {}", String::from_utf8_lossy(&list_out.stderr));
        }
        let listing = String::from_utf8_lossy(&list_out.stdout);
        let member = listing
            .lines()
            .map(str::trim)
            .find(|line| {
                !line.is_empty()
                    && !line.contains("..")
                    && !line.starts_with('/')
                    && (*line == "sing-box" || line.ends_with("/sing-box"))
            })
            .ok_or_else(|| anyhow!("sing-box binary not found inside tar.gz archive"))?
            .to_string();

        let ext_out = Command::new("tar")
            .arg("-xzOf")
            .arg(&tmp_path)
            .arg(&member)
            .output()
            .context("Failed to extract sing-box from tar.gz archive")?;
        if !ext_out.status.success() || ext_out.stdout.is_empty() {
            bail!(
                "tar extraction failed: {}",
                String::from_utf8_lossy(&ext_out.stderr)
            );
        }
        Ok(ext_out.stdout)
    })();

    let _ = std::fs::remove_file(&tmp_path);
    result
}

#[cfg(windows)]
fn extract_singbox_from_targz(_bytes: &[u8]) -> Result<Vec<u8>> {
    bail!("tar.gz sing-box archives are not used on Windows")
}

pub fn detect_version_at(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    let mut cmd = Command::new(path);
    cmd.arg("version");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("sing-box version ") {
            return Some(format!("v{}", rest.trim()));
        }
    }
    None
}

fn ensure_executable_bit(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(_path, perms)?;
    }
    Ok(())
}

fn core_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "sing-box.exe"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "sing-box"
    }
}

fn target_asset_suffix() -> &'static str {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "-windows-amd64.zip"
    }
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        "-windows-arm64.zip"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "-darwin-arm64.tar.gz"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "-darwin-amd64.tar.gz"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "-linux-amd64.tar.gz"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "-linux-arm64.tar.gz"
    }
}

pub fn compute_file_sha256(path: &Path) -> Result<String> {
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
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn stage_local_binary_preserves_existing_core_when_candidate_invalid() {
        let dir = tempdir().unwrap();
        let mgr = CoreManager::new(dir.path().to_path_buf());
        let existing = mgr.binary_path();
        std::fs::write(&existing, b"working-existing-core").unwrap();

        let bad_src = dir.path().join("not-a-singbox.bin");
        std::fs::write(&bad_src, b"corrupt-payload").unwrap();

        let err = mgr.import_local_binary(&bad_src, None);
        assert!(err.is_err());
        // Existing core must remain completely untouched after rejected import.
        assert_eq!(std::fs::read(&existing).unwrap(), b"working-existing-core");
    }

    #[test]
    fn rollback_binary_restores_prev_backup() {
        let dir = tempdir().unwrap();
        let mgr = CoreManager::new(dir.path().to_path_buf());
        let dest = mgr.binary_path();
        let backup = mgr.backup_binary_path();
        std::fs::write(&dest, b"broken-new").unwrap();
        std::fs::write(&backup, b"healthy-old").unwrap();

        assert!(mgr.rollback_binary().unwrap());
        assert_eq!(std::fs::read(&dest).unwrap(), b"healthy-old");
        assert!(!backup.exists());
    }
}
