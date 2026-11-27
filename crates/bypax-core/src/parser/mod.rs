pub mod clash_yaml;
pub mod singbox_json;
pub mod uri;

use crate::model::NodeIR;
use anyhow::Result;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    pub nodes: Vec<NodeIR>,
    pub skipped: usize,
    pub warnings: Vec<String>,
}

/// Auto-detects format (sing-box JSON, Clash YAML, raw URI lines, or Base64 subscription)
/// and parses all supported nodes into strongly typed `NodeIR`.
pub fn parse_payload(raw: &str, default_group: &str) -> Result<ImportSummary> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(ImportSummary {
            nodes: Vec::new(),
            skipped: 0,
            warnings: Vec::new(),
        });
    }

    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(summary) = singbox_json::parse_singbox_json(trimmed, default_group) {
            if !summary.nodes.is_empty() {
                return Ok(summary);
            }
        }
    }

    if trimmed.contains("proxies:") && !trimmed.contains("://") {
        if let Ok(summary) = clash_yaml::parse_clash_yaml(trimmed, default_group) {
            if !summary.nodes.is_empty() {
                return Ok(summary);
            }
        }
    }

    // Try direct URI lines first; if none found, attempt Base64 subscription decode.
    let direct = uri::parse_uri_batch(trimmed, default_group);
    if !direct.nodes.is_empty() {
        return Ok(direct);
    }

    if let Some(decoded) = uri::try_decode_base64_text(trimmed) {
        let decoded_trim = decoded.trim();
        if decoded_trim.contains("proxies:") && !decoded_trim.contains("://") {
            if let Ok(summary) = clash_yaml::parse_clash_yaml(decoded_trim, default_group) {
                if !summary.nodes.is_empty() {
                    return Ok(summary);
                }
            }
        }
        return Ok(uri::parse_uri_batch(decoded_trim, default_group));
    }

    // Last attempt: Clash YAML even if URIs existed in comments
    if trimmed.contains("proxies:") {
        if let Ok(summary) = clash_yaml::parse_clash_yaml(trimmed, default_group) {
            if !summary.nodes.is_empty() {
                return Ok(summary);
            }
        }
    }

    Ok(direct)
}

/// Normalizes Hysteria2 port-hopping specifications (`"20000-30000,40000"`, `"20000:30000"`)
/// into strict sing-box v1.14 `server_ports` range entries (`"start:end"`).
pub(crate) fn normalize_port_ranges(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in raw.split([',', ';']) {
        let part = token.trim();
        if part.is_empty() {
            continue;
        }
        let parsed = if let Some((a, b)) = part.split_once(':') {
            parse_port_pair(a, b)
        } else if let Some((a, b)) = part.split_once('-') {
            parse_port_pair(a, b)
        } else {
            part.parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
                .map(|p| (p, p))
        };
        if let Some((start, end)) = parsed {
            let formatted = format!("{}:{}", start, end);
            if !out.contains(&formatted) {
                out.push(formatted);
            }
        }
    }
    out
}

fn parse_port_pair(a: &str, b: &str) -> Option<(u16, u16)> {
    let start = a.trim().parse::<u16>().ok().filter(|&p| p > 0)?;
    let end = b.trim().parse::<u16>().ok().filter(|&p| p > 0)?;
    if start <= end {
        Some((start, end))
    } else {
        Some((end, start))
    }
}

/// Extracts the first valid starting port from normalized `start:end` ranges.
pub(crate) fn first_port_from_ranges(ranges: &[String]) -> Option<u16> {
    ranges.iter().find_map(|r| {
        r.split_once(':')
            .and_then(|(start, _)| start.parse::<u16>().ok())
            .filter(|&p| p > 0)
    })
}

/// Parses bandwidth values such as `"100"`, `"100 Mbps"`, `"100mbps"`, or `"1 Gbps"` into Mbps.
pub(crate) fn parse_bandwidth_mbps(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let (num_str, multiplier) = if let Some(v) = lower.strip_suffix("gbps") {
        (v.trim(), 1000u32)
    } else if let Some(v) = lower.strip_suffix("g") {
        (v.trim(), 1000u32)
    } else if let Some(v) = lower.strip_suffix("mbps") {
        (v.trim(), 1u32)
    } else if let Some(v) = lower.strip_suffix("m") {
        (v.trim(), 1u32)
    } else {
        (lower.as_str(), 1u32)
    };
    let val = num_str.parse::<u32>().ok().filter(|&v| v > 0)?;
    val.checked_mul(multiplier)
}

/// Normalizes hop interval inputs (`"30"`, `"30s"`, `"1m"`) into a sing-box duration string.
pub(crate) fn normalize_hop_interval(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        let secs = trimmed.parse::<u64>().ok().filter(|&s| s > 0)?;
        return Some(format!("{}s", secs));
    }
    Some(trimmed.to_string())
}
