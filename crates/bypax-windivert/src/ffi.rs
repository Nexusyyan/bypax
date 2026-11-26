//! Exact WinDivert 2.2 C ABI definitions verified against official `include/windivert.h`.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type Handle = *mut c_void;
pub const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

pub const WINDIVERT_LAYER_NETWORK: u32 = 0;
pub const WINDIVERT_LAYER_NETWORK_FORWARD: u32 = 1;
pub const WINDIVERT_LAYER_FLOW: u32 = 2;
pub const WINDIVERT_LAYER_SOCKET: u32 = 3;
pub const WINDIVERT_LAYER_REFLECT: u32 = 4;

pub const WINDIVERT_EVENT_NETWORK_PACKET: u8 = 0;
pub const WINDIVERT_EVENT_FLOW_ESTABLISHED: u8 = 1;
pub const WINDIVERT_EVENT_FLOW_DELETED: u8 = 2;
pub const WINDIVERT_EVENT_SOCKET_BIND: u8 = 3;
pub const WINDIVERT_EVENT_SOCKET_CONNECT: u8 = 4;
pub const WINDIVERT_EVENT_SOCKET_LISTEN: u8 = 5;
pub const WINDIVERT_EVENT_SOCKET_ACCEPT: u8 = 6;
pub const WINDIVERT_EVENT_SOCKET_CLOSE: u8 = 7;

pub const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
pub const WINDIVERT_FLAG_DROP: u64 = 0x0002;
pub const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
pub const WINDIVERT_FLAG_SEND_ONLY: u64 = 0x0008;
pub const WINDIVERT_FLAG_NO_INSTALL: u64 = 0x0010;
pub const WINDIVERT_FLAG_FRAGMENTS: u64 = 0x0020;

pub const WINDIVERT_PARAM_QUEUE_LENGTH: u32 = 0;
pub const WINDIVERT_PARAM_QUEUE_TIME: u32 = 1;
pub const WINDIVERT_PARAM_QUEUE_SIZE: u32 = 2;
pub const WINDIVERT_PARAM_VERSION_MAJOR: u32 = 3;
pub const WINDIVERT_PARAM_VERSION_MINOR: u32 = 4;

pub const WINDIVERT_SHUTDOWN_RECV: u32 = 0x1;
pub const WINDIVERT_SHUTDOWN_SEND: u32 = 0x2;
pub const WINDIVERT_SHUTDOWN_BOTH: u32 = 0x3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct WinDivertDataNetwork {
    pub if_idx: u32,
    pub sub_if_idx: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct WinDivertDataFlow {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

pub type WinDivertDataSocket = WinDivertDataFlow;

#[repr(C)]
#[derive(Clone, Copy)]
pub union WinDivertDataUnion {
    pub network: WinDivertDataNetwork,
    pub flow: WinDivertDataFlow,
    pub socket: WinDivertDataSocket,
    pub reserved3: [u8; 64],
}

impl Default for WinDivertDataUnion {
    fn default() -> Self {
        Self { reserved3: [0u8; 64] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    pub flags: u32,
    pub reserved2: u32,
    pub data: WinDivertDataUnion,
}

impl WinDivertAddress {
    #[inline]
    pub fn layer(&self) -> u8 {
        (self.flags & 0xFF) as u8
    }

    #[inline]
    pub fn set_layer(&mut self, layer: u8) {
        self.flags = (self.flags & !0xFF) | (layer as u32);
    }

    #[inline]
    pub fn event(&self) -> u8 {
        ((self.flags >> 8) & 0xFF) as u8
    }

    #[inline]
    pub fn outbound(&self) -> bool {
        (self.flags & (1 << 17)) != 0
    }

    #[inline]
    pub fn set_outbound(&mut self, val: bool) {
        if val {
            self.flags |= 1 << 17;
        } else {
            self.flags &= !(1 << 17);
        }
    }

    #[inline]
    pub fn ipv6(&self) -> bool {
        (self.flags & (1 << 20)) != 0
    }

    #[inline]
    pub fn set_ipv6(&mut self, val: bool) {
        if val {
            self.flags |= 1 << 20;
        } else {
            self.flags &= !(1 << 20);
        }
    }

    #[inline]
    pub fn network(&self) -> WinDivertDataNetwork {
        unsafe { self.data.network }
    }

    #[inline]
    pub fn set_network(&mut self, net: WinDivertDataNetwork) {
        self.data.network = net;
    }

    #[inline]
    pub fn socket(&self) -> WinDivertDataSocket {
        unsafe { self.data.socket }
    }
}

pub fn decode_windivert_addr(raw: [u32; 4], is_ipv6: bool) -> IpAddr {
    if !is_ipv6 {
        return IpAddr::V4(Ipv4Addr::from(raw[0]));
    }
    if raw[3] == 0 && raw[2] == 0 && raw[1] == 0x0000_FFFF {
        return IpAddr::V4(Ipv4Addr::from(raw[0]));
    }
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&raw[3].to_be_bytes());
    bytes[4..8].copy_from_slice(&raw[2].to_be_bytes());
    bytes[8..12].copy_from_slice(&raw[1].to_be_bytes());
    bytes[12..16].copy_from_slice(&raw[0].to_be_bytes());
    IpAddr::V6(Ipv6Addr::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn windivert_abi_layout_matches_header() {
        assert_eq!(size_of::<WinDivertDataNetwork>(), 8);
        assert_eq!(size_of::<WinDivertDataFlow>(), 64);
        assert_eq!(size_of::<WinDivertAddress>(), 80);
        assert_eq!(align_of::<WinDivertAddress>(), 8);
        assert_eq!(offset_of!(WinDivertAddress, data), 16);
        assert_eq!(offset_of!(WinDivertDataFlow, process_id), 16);
    }
}
