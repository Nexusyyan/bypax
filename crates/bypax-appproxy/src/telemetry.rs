use bypax_ipc::{AppProxyLocalConnectionDto, AppProxyLocalStatsDto};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

const MAX_LOCAL_CONNECTIONS: usize = 200;

/// Zero-double-counting telemetry store for `bypax-appproxy`.
///
/// Connections forwarded into `sing-box`'s `app-proxy-in` are metered authoritatively by
/// `sing-box` Clash API `/connections` (attributed via `OriginRegistry`), so this hub tracks
/// only connection counts for proxied flows and full byte/connection records for **local**
/// (non-core) `local_direct` and `local_reject` flows.
#[derive(Default)]
pub struct AppProxyTelemetry {
    next_id: AtomicU64,
    local_direct_bytes_tx: AtomicU64,
    local_direct_bytes_rx: AtomicU64,
    local_direct_connections: AtomicU64,
    local_reject_connections: AtomicU64,
    proxied_connections: AtomicU64,
    active_proxied_connections: AtomicU64,
    local_connections: RwLock<VecDeque<AppProxyLocalConnectionDto>>,
}

impl AppProxyTelemetry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn on_proxied_open(&self) {
        self.proxied_connections.fetch_add(1, Ordering::Relaxed);
        self.active_proxied_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_proxied_close(&self) {
        decrement_saturating(&self.active_proxied_connections);
    }

    pub fn open_local_direct(
        &self,
        pid: Option<u32>,
        process_name: String,
        ancestor_app: Option<String>,
        ancestor_chain: Vec<String>,
        destination: String,
        rule_name: String,
    ) -> String {
        let id = format!("ap-dir-{}", self.next_id.fetch_add(1, Ordering::Relaxed) + 1);
        self.local_direct_connections.fetch_add(1, Ordering::Relaxed);
        let rec = AppProxyLocalConnectionDto {
            id: id.clone(),
            pid,
            process_name,
            ancestor_app,
            ancestor_chain,
            destination,
            rule_name,
            local_action: "local_direct".to_string(),
            upload_bytes: 0,
            download_bytes: 0,
            started_at: chrono::Utc::now().to_rfc3339(),
            active: true,
        };
        if let Ok(mut list) = self.local_connections.write() {
            list.push_front(rec);
            while list.len() > MAX_LOCAL_CONNECTIONS {
                list.pop_back();
            }
        }
        id
    }

    pub fn add_local_direct_bytes(&self, id: &str, tx: u64, rx: u64) {
        if tx > 0 {
            self.local_direct_bytes_tx.fetch_add(tx, Ordering::Relaxed);
        }
        if rx > 0 {
            self.local_direct_bytes_rx.fetch_add(rx, Ordering::Relaxed);
        }
        if let Ok(mut list) = self.local_connections.write() {
            if let Some(item) = list.iter_mut().find(|c| c.id == id) {
                item.upload_bytes = item.upload_bytes.saturating_add(tx);
                item.download_bytes = item.download_bytes.saturating_add(rx);
            }
        }
    }

    pub fn close_local_direct(&self, id: &str) {
        if let Ok(mut list) = self.local_connections.write() {
            if let Some(item) = list.iter_mut().find(|c| c.id == id) {
                item.active = false;
            }
        }
    }

    pub fn record_local_reject(
        &self,
        pid: Option<u32>,
        process_name: String,
        ancestor_app: Option<String>,
        ancestor_chain: Vec<String>,
        destination: String,
        rule_name: String,
    ) {
        let id = format!("ap-blk-{}", self.next_id.fetch_add(1, Ordering::Relaxed) + 1);
        self.local_reject_connections.fetch_add(1, Ordering::Relaxed);
        let rec = AppProxyLocalConnectionDto {
            id,
            pid,
            process_name,
            ancestor_app,
            ancestor_chain,
            destination,
            rule_name,
            local_action: "local_reject".to_string(),
            upload_bytes: 0,
            download_bytes: 0,
            started_at: chrono::Utc::now().to_rfc3339(),
            active: false,
        };
        if let Ok(mut list) = self.local_connections.write() {
            list.push_front(rec);
            while list.len() > MAX_LOCAL_CONNECTIONS {
                list.pop_back();
            }
        }
    }

    pub fn snapshot(&self) -> AppProxyLocalStatsDto {
        let local_connections = self
            .local_connections
            .read()
            .map(|l| l.iter().cloned().collect())
            .unwrap_or_default();
        AppProxyLocalStatsDto {
            local_direct_bytes_tx: self.local_direct_bytes_tx.load(Ordering::Relaxed),
            local_direct_bytes_rx: self.local_direct_bytes_rx.load(Ordering::Relaxed),
            local_direct_connections: self.local_direct_connections.load(Ordering::Relaxed),
            local_reject_connections: self.local_reject_connections.load(Ordering::Relaxed),
            proxied_connections: self.proxied_connections.load(Ordering::Relaxed),
            active_proxied_connections: self.active_proxied_connections.load(Ordering::Relaxed),
            local_connections,
        }
    }
}

fn decrement_saturating(counter: &AtomicU64) {
    let mut cur = counter.load(Ordering::Relaxed);
    while cur > 0 {
        match counter.compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => cur = next,
        }
    }
}
