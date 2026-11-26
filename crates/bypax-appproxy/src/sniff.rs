/// Result of protocol sniffing on the initial payload of a TCP or UDP flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffResult {
    /// Hostname extracted from TLS ClientHello Server Name Indication (SNI).
    TlsSni(String),
    /// Hostname extracted from an HTTP/1.x `Host` request header.
    HttpHost(String),
    /// RFC 9000 / RFC 9369 QUIC Long Header Initial packet detected.
    QuicInitial,
}

/// Attempts to sniff a domain name from the first payload bytes of a TCP stream.
pub fn sniff_tcp_payload(data: &[u8]) -> Option<SniffResult> {
    if let Some(sni) = sniff_tls_sni(data) {
        return Some(SniffResult::TlsSni(sni));
    }
    if let Some(host) = sniff_http_host(data) {
        return Some(SniffResult::HttpHost(host));
    }
    None
}

/// Inspects a UDP datagram payload to detect QUIC Initial packets (v1 & v2).
pub fn sniff_udp_payload(data: &[u8]) -> Option<SniffResult> {
    if is_quic_initial(data) {
        return Some(SniffResult::QuicInitial);
    }
    None
}

/// Returns true when `data` begins a TLS Handshake record whose full body (including large
/// post-quantum `X25519MLKEM768` key_share extensions > 1460B MSS) has not yet arrived.
pub fn needs_more_tls_bytes(data: &[u8], max_buffer: usize) -> bool {
    if data.len() < 2 || data[0] != 0x16 || data[1] != 0x03 {
        return false;
    }
    if data.len() < 5 {
        return true;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let total_needed = 5usize.saturating_add(record_len).min(max_buffer);
    data.len() < total_needed
}

/// Extracts the SNI hostname from a TLS 1.0-1.3 ClientHello (including multi-record or PQ-TLS
/// ClientHello payloads with large key_share extensions).
pub fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }

    // Reassemble contiguous TLS handshake records in case a PQ ClientHello is split across
    // multiple TLS records inside the accumulated TCP buffer.
    let mut hs_buf: Vec<u8> = Vec::new();
    let mut rec_pos = 0usize;
    while rec_pos + 5 <= data.len() && data[rec_pos] == 0x16 && data[rec_pos + 1] == 0x03 {
        let rec_len = u16::from_be_bytes([data[rec_pos + 3], data[rec_pos + 4]]) as usize;
        let body_start = rec_pos + 5;
        let body_end = (body_start + rec_len).min(data.len());
        hs_buf.extend_from_slice(&data[body_start..body_end]);
        if body_start + rec_len > data.len() {
            break;
        }
        rec_pos = body_end;
        if hs_buf.len() >= 16_384 {
            break;
        }
    }

    let hs = &hs_buf;
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let mut pos = 4usize;

    // client_version (2) + random (32)
    if hs.len() < pos + 34 {
        return None;
    }
    pos += 34;

    // session_id
    if hs.len() < pos + 1 {
        return None;
    }
    let session_id_len = hs[pos] as usize;
    pos += 1 + session_id_len;

    // cipher_suites
    if hs.len() < pos + 2 {
        return None;
    }
    let cipher_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // compression_methods
    if hs.len() < pos + 1 {
        return None;
    }
    let comp_len = hs[pos] as usize;
    pos += 1 + comp_len;

    // extensions
    if hs.len() < pos + 2 {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;

    let ext_end = (pos + ext_total_len).min(hs.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            let ext = &hs[pos..pos + ext_len];
            let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
            let mut sni_pos = 2usize;
            let list_end = (2 + list_len).min(ext.len());
            while sni_pos + 3 <= list_end {
                let name_type = ext[sni_pos];
                let name_len = u16::from_be_bytes([ext[sni_pos + 1], ext[sni_pos + 2]]) as usize;
                sni_pos += 3;
                if sni_pos + name_len > list_end {
                    break;
                }
                if name_type == 0x00 {
                    let raw = &ext[sni_pos..sni_pos + name_len];
                    if let Ok(host) = std::str::from_utf8(raw) {
                        if is_valid_hostname(host) {
                            return Some(host.to_ascii_lowercase());
                        }
                    }
                }
                sni_pos += name_len;
            }
        }
        pos += ext_len;
    }
    None
}

/// Extracts the `Host` header value from an HTTP/1.x request.
pub fn sniff_http_host(data: &[u8]) -> Option<String> {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    if !METHODS.iter().any(|m| data.starts_with(m)) {
        return None;
    }

    let text = std::str::from_utf8(&data[..data.len().min(4096)]).ok()?;
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let val = v.trim();
                let host = if val.starts_with('[') {
                    val.split(']').next()?.trim_start_matches('[')
                } else {
                    val.split(':').next()?
                };
                if is_valid_hostname(host) {
                    return Some(host.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

/// Checks whether a UDP datagram matches RFC 9000 / RFC 9369 QUIC Initial Long Header format.
pub fn is_quic_initial(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }
    let first = data[0];
    if (first & 0xC0) != 0xC0 {
        return false;
    }
    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let long_type = (first >> 4) & 0x03;

    let valid_version_type =
        (version == 0x0000_0001 && long_type == 0) || (version == 0x6b33_43cf && long_type == 1);
    if !valid_version_type {
        return false;
    }

    let dcid_len = data[5] as usize;
    if dcid_len > 20 || data.len() < 7 + dcid_len {
        return false;
    }
    let scid_len = data[6 + dcid_len] as usize;
    scid_len <= 20 && data.len() >= 7 + dcid_len + scid_len
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pq_client_hello_with_sni(hostname: &str, key_share_padding: usize) -> Vec<u8> {
        let mut extensions = Vec::new();
        // Simulated X25519MLKEM768 key_share extension (type 0x0033) placed BEFORE SNI so
        // SNI lies past the 1460-byte TCP MSS boundary.
        let ks_body = vec![0x42u8; key_share_padding];
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&(ks_body.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ks_body);

        let host_bytes = hostname.as_bytes();
        let mut sni_ext = Vec::new();
        let list_len = (1 + 2 + host_bytes.len()) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host_bytes);

        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAA; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let hs_len = body.len();
        handshake.push(((hs_len >> 16) & 0xFF) as u8);
        handshake.push(((hs_len >> 8) & 0xFF) as u8);
        handshake.push((hs_len & 0xFF) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_pq_tls_sni_beyond_1460_mss_and_detects_truncation() {
        let hello = build_pq_client_hello_with_sni("cloudcode-pa.googleapis.com", 1600);
        assert!(hello.len() > 1650);
        // First 1460 bytes are incomplete -> needs_more_tls_bytes returns true.
        assert!(needs_more_tls_bytes(&hello[..1460], 8192));
        assert_eq!(sniff_tls_sni(&hello[..1460]), None);
        // Once second segment arrives, SNI is cleanly recovered!
        assert!(!needs_more_tls_bytes(&hello, 8192));
        assert_eq!(
            sniff_tcp_payload(&hello),
            Some(SniffResult::TlsSni(
                "cloudcode-pa.googleapis.com".to_string()
            ))
        );
    }

    #[test]
    fn extracts_http_host_and_quic_initial() {
        let req = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n";
        assert_eq!(
            sniff_tcp_payload(req),
            Some(SniffResult::HttpHost("api.openai.com".to_string()))
        );

        let mut pkt_v1 = vec![0u8; 32];
        pkt_v1[0] = 0xC3;
        pkt_v1[1..5].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        pkt_v1[5] = 8;
        assert_eq!(sniff_udp_payload(&pkt_v1), Some(SniffResult::QuicInitial));
    }
}
