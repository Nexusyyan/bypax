use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc;

/// Layer-4 transport protocol supported by the transparent application proxy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportProtocol::Tcp => write!(f, "TCP"),
            TransportProtocol::Udp => write!(f, "UDP"),
        }
    }
}

/// Network 5-tuple identifying a unidirectional packet flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub protocol: TransportProtocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl FiveTuple {
    pub fn reversed(&self) -> Self {
        Self {
            protocol: self.protocol,
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

/// Interface metadata preserved across userspace netstack round-trips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    pub iface_index: u32,
    pub sub_iface_index: u32,
    pub outbound: bool,
    pub is_ipv6: bool,
}

impl PacketMeta {
    pub fn as_inbound_reply(&self) -> Self {
        Self {
            iface_index: self.iface_index,
            sub_iface_index: self.sub_iface_index,
            outbound: false,
            is_ipv6: self.is_ipv6,
        }
    }
}

/// Raw IP packet captured from the OS network stack.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub payload: Vec<u8>,
    pub meta: PacketMeta,
}

/// Platform-agnostic packet capture backend abstraction.
///
/// - Windows: implemented via dynamically loaded WinDivert 2.2+ (`bypax-windivert`)
/// - macOS: zero-cert `launchd` + `sing-box` `utun` path routing handled at compiler/service layer
pub trait CaptureEngine: Send + Sync + 'static {
    fn start(&self, tx: mpsc::Sender<CapturedPacket>) -> anyhow::Result<()>;
    fn inject(&self, packet: &[u8], meta: &PacketMeta) -> anyhow::Result<()>;
    fn lookup_pid(&self, tuple: &FiveTuple) -> Option<u32>;
    fn find_local_tcp_listener_pid(&self, port: u16) -> Option<u32>;
    fn shutdown(&self) -> anyhow::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPacketHeader {
    pub tuple: FiveTuple,
    pub is_ipv6: bool,
    pub ip_header_len: usize,
    pub l4_offset: usize,
    pub l4_payload_offset: usize,
    pub tcp_flags: u8,
}

pub fn parse_ip_packet(packet: &[u8]) -> Option<ParsedPacketHeader> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<ParsedPacketHeader> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let frag_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (frag_field & 0x1FFF) != 0 {
        return None;
    }
    let proto_num = packet[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
    parse_l4(packet, ihl, proto_num, src_ip, dst_ip, false)
}

fn parse_ipv6(packet: &[u8]) -> Option<ParsedPacketHeader> {
    if packet.len() < 40 {
        return None;
    }
    let next_hdr = packet[6];
    let src_bytes: [u8; 16] = packet[8..24].try_into().ok()?;
    let dst_bytes: [u8; 16] = packet[24..40].try_into().ok()?;
    let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

    let mut offset = 40usize;
    let mut proto = next_hdr;
    for _ in 0..8 {
        match proto {
            0 | 43 | 60 => {
                if packet.len() < offset + 2 {
                    return None;
                }
                let next = packet[offset];
                let ext_len = (packet[offset + 1] as usize + 1) * 8;
                if packet.len() < offset + ext_len {
                    return None;
                }
                offset += ext_len;
                proto = next;
            }
            44 => {
                if packet.len() < offset + 8 {
                    return None;
                }
                let frag_off = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) >> 3;
                if frag_off != 0 {
                    return None;
                }
                proto = packet[offset];
                offset += 8;
            }
            _ => break,
        }
    }
    parse_l4(packet, offset, proto, src_ip, dst_ip, true)
}

fn parse_l4(
    packet: &[u8],
    l4_offset: usize,
    proto_num: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    is_ipv6: bool,
) -> Option<ParsedPacketHeader> {
    match proto_num {
        6 => {
            if packet.len() < l4_offset + 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([packet[l4_offset], packet[l4_offset + 1]]);
            let dst_port = u16::from_be_bytes([packet[l4_offset + 2], packet[l4_offset + 3]]);
            let data_offset = ((packet[l4_offset + 12] >> 4) as usize) * 4;
            if data_offset < 20 || packet.len() < l4_offset + data_offset {
                return None;
            }
            let tcp_flags = packet[l4_offset + 13];
            Some(ParsedPacketHeader {
                tuple: FiveTuple {
                    protocol: TransportProtocol::Tcp,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                },
                is_ipv6,
                ip_header_len: l4_offset,
                l4_offset,
                l4_payload_offset: l4_offset + data_offset,
                tcp_flags,
            })
        }
        17 => {
            if packet.len() < l4_offset + 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([packet[l4_offset], packet[l4_offset + 1]]);
            let dst_port = u16::from_be_bytes([packet[l4_offset + 2], packet[l4_offset + 3]]);
            Some(ParsedPacketHeader {
                tuple: FiveTuple {
                    protocol: TransportProtocol::Udp,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                },
                is_ipv6,
                ip_header_len: l4_offset,
                l4_offset,
                l4_payload_offset: l4_offset + 8,
                tcp_flags: 0,
            })
        }
        _ => None,
    }
}

/// Builds a complete IPv4 or IPv6 UDP datagram with valid IP and UDP checksums.
pub fn build_udp_ip_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    if udp_len > u16::MAX as usize {
        return None;
    }

    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total_len = 20usize.checked_add(udp_len)?;
            if total_len > u16::MAX as usize {
                return None;
            }
            let mut buf = vec![0u8; total_len];
            buf[0] = 0x45;
            buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            buf[6] = 0x40;
            buf[8] = 64;
            buf[9] = 17;
            buf[12..16].copy_from_slice(&src.octets());
            buf[16..20].copy_from_slice(&dst.octets());

            let ip_csum = internet_checksum(&buf[0..20]);
            buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            buf[20..22].copy_from_slice(&src_port.to_be_bytes());
            buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
            buf[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
            buf[28..].copy_from_slice(payload);

            let udp_csum = ipv4_l4_checksum(src, dst, 17, &buf[20..]);
            buf[26..28].copy_from_slice(&udp_csum.to_be_bytes());
            Some(buf)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let total_len = 40usize.checked_add(udp_len)?;
            let mut buf = vec![0u8; total_len];
            buf[0] = 0x60;
            buf[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            buf[6] = 17;
            buf[7] = 64;
            buf[8..24].copy_from_slice(&src.octets());
            buf[24..40].copy_from_slice(&dst.octets());

            buf[40..42].copy_from_slice(&src_port.to_be_bytes());
            buf[42..44].copy_from_slice(&dst_port.to_be_bytes());
            buf[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
            buf[48..].copy_from_slice(payload);

            let udp_csum = ipv6_l4_checksum(src, dst, 17, &buf[40..]);
            buf[46..48].copy_from_slice(&udp_csum.to_be_bytes());
            Some(buf)
        }
        _ => None,
    }
}

fn checksum_sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let (chunks, remainder) = data.as_chunks::<2>();
    for c in chunks {
        sum += u16::from_be_bytes(*c) as u32;
    }
    if let Some(&rem) = remainder.first() {
        sum += (rem as u32) << 8;
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let result = !(sum as u16);
    if result == 0 {
        0xFFFF
    } else {
        result
    }
}

fn internet_checksum(header: &[u8]) -> u16 {
    let mut sum = checksum_sum(header);
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += checksum_sum(&src.octets());
    sum += checksum_sum(&dst.octets());
    sum += proto as u32;
    sum += l4.len() as u32;
    sum += checksum_sum(l4);
    finalize_checksum(sum)
}

fn ipv6_l4_checksum(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, l4: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += checksum_sum(&src.octets());
    sum += checksum_sum(&dst.octets());
    sum += (l4.len() as u32) >> 16;
    sum += (l4.len() as u32) & 0xFFFF;
    sum += proto as u32;
    sum += checksum_sum(l4);
    finalize_checksum(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_ipv4_and_ipv6_udp_roundtrip() {
        let src4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let dst4 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let pkt4 = build_udp_ip_packet(src4, 51234, dst4, 53, b"hello").unwrap();
        let parsed4 = parse_ip_packet(&pkt4).unwrap();
        assert!(!parsed4.is_ipv6);
        assert_eq!(parsed4.tuple.protocol, TransportProtocol::Udp);
        assert_eq!(&pkt4[parsed4.l4_payload_offset..], b"hello");

        let src6 = IpAddr::V6("2001:db8::1".parse().unwrap());
        let dst6 = IpAddr::V6("2001:4860:4860::8888".parse().unwrap());
        let pkt6 = build_udp_ip_packet(src6, 44321, dst6, 443, b"quic").unwrap();
        let parsed6 = parse_ip_packet(&pkt6).unwrap();
        assert!(parsed6.is_ipv6);
        assert_eq!(&pkt6[parsed6.l4_payload_offset..], b"quic");
    }
}
