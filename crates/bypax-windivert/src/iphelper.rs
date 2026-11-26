//! Windows IP Helper API fallback (`GetExtendedTcpTable` / `GetExtendedUdpTable`)
//! for race-free first-packet PID resolution and local upstream listener discovery.

use bypax_appproxy::capture::{FiveTuple, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
    TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

pub fn lookup_pid_from_os_table(tuple: &FiveTuple) -> Option<u32> {
    match tuple.protocol {
        TransportProtocol::Tcp => match tuple.src_ip {
            IpAddr::V4(v4) => lookup_tcp_v4(v4, tuple.src_port, tuple.dst_ip, tuple.dst_port),
            IpAddr::V6(v6) => lookup_tcp_v6(v6, tuple.src_port, tuple.dst_ip, tuple.dst_port),
        },
        TransportProtocol::Udp => match tuple.src_ip {
            IpAddr::V4(v4) => lookup_udp_v4(v4, tuple.src_port),
            IpAddr::V6(v6) => lookup_udp_v6(v6, tuple.src_port),
        },
    }
}

pub fn find_tcp_listener_pid(port: u16) -> Option<u32> {
    find_tcp_v4_listener_pid(port).or_else(|| find_tcp_v6_listener_pid(port))
}

fn aligned_u32_buf(byte_len: usize, min_bytes: usize) -> Vec<u32> {
    let bytes = byte_len.max(min_bytes);
    vec![0u32; bytes.div_ceil(4)]
}

fn port_from_mib(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}

fn lookup_tcp_v4(src_ip: Ipv4Addr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Option<u32> {
    let dst_v4 = match dst_ip {
        IpAddr::V4(v) => v,
        _ => return None,
    };
    unsafe {
        let mut size = 0u32;
        let res = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        );
        if res != ERROR_INSUFFICIENT_BUFFER.0 && res != NO_ERROR.0 {
            return None;
        }
        let mut buf = aligned_u32_buf(size as usize, std::mem::size_of::<MIB_TCPTABLE_OWNER_PID>());
        if GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        ) != NO_ERROR.0
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows_ptr = table.table.as_ptr();
        let mut fallback = None;
        for i in 0..(table.dwNumEntries as usize) {
            let row: &MIB_TCPROW_OWNER_PID = &*rows_ptr.add(i);
            let lport = port_from_mib(row.dwLocalPort);
            let rport = port_from_mib(row.dwRemotePort);
            if lport != src_port {
                continue;
            }
            let lip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            let rip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
            if lip == src_ip && rip == dst_v4 && rport == dst_port {
                return Some(row.dwOwningPid);
            }
            if rport == dst_port && rip == dst_v4 {
                fallback = Some(row.dwOwningPid);
            }
        }
        fallback
    }
}

fn lookup_tcp_v6(src_ip: Ipv6Addr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Option<u32> {
    let dst_v6 = match dst_ip {
        IpAddr::V6(v) => v,
        _ => return None,
    };
    unsafe {
        let mut size = 0u32;
        let res = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        );
        if res != ERROR_INSUFFICIENT_BUFFER.0 && res != NO_ERROR.0 {
            return None;
        }
        let mut buf = aligned_u32_buf(size as usize, std::mem::size_of::<MIB_TCP6TABLE_OWNER_PID>());
        if GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        ) != NO_ERROR.0
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows_ptr = table.table.as_ptr();
        for i in 0..(table.dwNumEntries as usize) {
            let row: &MIB_TCP6ROW_OWNER_PID = &*rows_ptr.add(i);
            if port_from_mib(row.dwLocalPort) == src_port
                && port_from_mib(row.dwRemotePort) == dst_port
                && Ipv6Addr::from(row.ucLocalAddr) == src_ip
                && Ipv6Addr::from(row.ucRemoteAddr) == dst_v6
            {
                return Some(row.dwOwningPid);
            }
        }
        None
    }
}

fn lookup_udp_v4(src_ip: Ipv4Addr, src_port: u16) -> Option<u32> {
    unsafe {
        let mut size = 0u32;
        let res = GetExtendedUdpTable(None, &mut size, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0);
        if res != ERROR_INSUFFICIENT_BUFFER.0 && res != NO_ERROR.0 {
            return None;
        }
        let mut buf = aligned_u32_buf(size as usize, std::mem::size_of::<MIB_UDPTABLE_OWNER_PID>());
        if GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ) != NO_ERROR.0
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows_ptr = table.table.as_ptr();
        let mut wildcard = None;
        for i in 0..(table.dwNumEntries as usize) {
            let row: &MIB_UDPROW_OWNER_PID = &*rows_ptr.add(i);
            if port_from_mib(row.dwLocalPort) != src_port {
                continue;
            }
            let lip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            if lip == src_ip {
                return Some(row.dwOwningPid);
            }
            if lip.is_unspecified() {
                wildcard = Some(row.dwOwningPid);
            }
        }
        wildcard
    }
}

fn lookup_udp_v6(src_ip: Ipv6Addr, src_port: u16) -> Option<u32> {
    unsafe {
        let mut size = 0u32;
        let res =
            GetExtendedUdpTable(None, &mut size, false, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0);
        if res != ERROR_INSUFFICIENT_BUFFER.0 && res != NO_ERROR.0 {
            return None;
        }
        let mut buf = aligned_u32_buf(size as usize, std::mem::size_of::<MIB_UDP6TABLE_OWNER_PID>());
        if GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ) != NO_ERROR.0
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let rows_ptr = table.table.as_ptr();
        let mut wildcard = None;
        for i in 0..(table.dwNumEntries as usize) {
            let row: &MIB_UDP6ROW_OWNER_PID = &*rows_ptr.add(i);
            if port_from_mib(row.dwLocalPort) != src_port {
                continue;
            }
            let lip = Ipv6Addr::from(row.ucLocalAddr);
            if lip == src_ip {
                return Some(row.dwOwningPid);
            }
            if lip.is_unspecified() {
                wildcard = Some(row.dwOwningPid);
            }
        }
        wildcard
    }
}

fn find_tcp_v4_listener_pid(port: u16) -> Option<u32> {
    unsafe {
        let mut size = 0u32;
        let res = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if res != ERROR_INSUFFICIENT_BUFFER.0 && res != NO_ERROR.0 {
            return None;
        }
        let mut buf = aligned_u32_buf(size as usize, std::mem::size_of::<MIB_TCPTABLE_OWNER_PID>());
        if GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        ) != NO_ERROR.0
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows_ptr = table.table.as_ptr();
        for i in 0..(table.dwNumEntries as usize) {
            let row: &MIB_TCPROW_OWNER_PID = &*rows_ptr.add(i);
            if port_from_mib(row.dwLocalPort) == port {
                return Some(row.dwOwningPid);
            }
        }
        None
    }
}

fn find_tcp_v6_listener_pid(port: u16) -> Option<u32> {
    unsafe {
        let mut size = 0u32;
        let res = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if res != ERROR_INSUFFICIENT_BUFFER.0 && res != NO_ERROR.0 {
            return None;
        }
        let mut buf = aligned_u32_buf(size as usize, std::mem::size_of::<MIB_TCP6TABLE_OWNER_PID>());
        if GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        ) != NO_ERROR.0
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows_ptr = table.table.as_ptr();
        for i in 0..(table.dwNumEntries as usize) {
            let row: &MIB_TCP6ROW_OWNER_PID = &*rows_ptr.add(i);
            if port_from_mib(row.dwLocalPort) == port {
                return Some(row.dwOwningPid);
            }
        }
        None
    }
}
