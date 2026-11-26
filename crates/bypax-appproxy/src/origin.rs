use bypax_ipc::FlowOriginDto;
use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Closed flow origins are retained for 30 seconds so `/connections` polling can still attribute
/// short-lived flows accurately without showing `bypax-service.exe`.
pub const ORIGIN_RETENTION_TTL: Duration = Duration::from_secs(30);

struct StoredOrigin {
    origin: FlowOriginDto,
    closed_at: Option<Instant>,
}

/// Maps local ephemeral ports dialed into `127.0.0.1:{app_proxy_port}` back to the real
/// originating OS process, ancestor chain, and matched App Proxy rule.
#[derive(Default)]
pub struct OriginRegistry {
    by_port: DashMap<u16, StoredOrigin>,
}

impl OriginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, origin: FlowOriginDto) {
        let port = origin.local_port;
        self.by_port.insert(
            port,
            StoredOrigin {
                origin,
                closed_at: None,
            },
        );
    }

    pub fn mark_closed(&self, local_port: u16) {
        if let Some(mut entry) = self.by_port.get_mut(&local_port) {
            entry.closed_at = Some(Instant::now());
        }
    }

    /// Looks up a batch of local ephemeral ports; expired or unknown ports are returned with
    /// `expired: true` only when not found in cache? No: return found (non-expired) records,
    /// allowing the caller to mark any unresolved `app-proxy-in` connection as `origin_expired`.
    pub fn lookup_batch(&self, local_ports: &[u16]) -> Vec<FlowOriginDto> {
        let now = Instant::now();
        let mut out = Vec::with_capacity(local_ports.len());
        for &port in local_ports {
            if let Some(entry) = self.by_port.get(&port) {
                let expired = entry
                    .closed_at
                    .map(|t| now.duration_since(t) > ORIGIN_RETENTION_TTL)
                    .unwrap_or(false);
                if !expired {
                    out.push(entry.origin.clone());
                }
            }
        }
        out
    }

    pub fn gc_expired(&self) {
        let now = Instant::now();
        self.by_port.retain(|_, v| {
            v.closed_at
                .map(|t| now.duration_since(t) <= ORIGIN_RETENTION_TTL)
                .unwrap_or(true)
        });
    }

    pub fn len(&self) -> usize {
        self.by_port.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_port.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_registry_tracks_and_retains_closed_entries_within_ttl() {
        let reg = OriginRegistry::new();
        reg.register(FlowOriginDto {
            local_port: 54321,
            pid: 8810,
            process_name: "node.exe".to_string(),
            exe_path: Some(r"C:\Program Files\nodejs\node.exe".to_string()),
            ancestor_name: Some("Antigravity".to_string()),
            ancestor_chain: vec![
                "node.exe".to_string(),
                "language_server_windows_x64.exe".to_string(),
                "Antigravity.exe".to_string(),
            ],
            rule_id: Some("preset-antigravity".to_string()),
            rule_name: "Antigravity".to_string(),
            target: "follow".to_string(),
            auth_user: "bx_follow".to_string(),
            sniffed_host: Some("cloudcode-pa.googleapis.com".to_string()),
            action: "proxy".to_string(),
            expired: false,
        });

        reg.mark_closed(54321);
        let found = reg.lookup_batch(&[54321, 9999]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].process_name, "node.exe");
        assert_eq!(found[0].ancestor_name.as_deref(), Some("Antigravity"));
    }
}
