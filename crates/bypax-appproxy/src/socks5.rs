use anyhow::{anyhow, bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Target destination address passed to internal `sing-box` `app-proxy-in`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddr::Ip(sa) => write!(f, "{sa}"),
            TargetAddr::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

/// Connects to internal `127.0.0.1:{app_proxy_port}` with RFC 1929 `auth_user` + `password`
/// authentication and returns `(TcpStream, local_ephemeral_port)` so `OriginRegistry` can
/// immediately record the exact local source port before sending payload data.
pub async fn connect_internal_tcp(
    app_proxy_port: u16,
    auth_user: &str,
    password: &str,
    target: &TargetAddr,
) -> Result<(TcpStream, u16)> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), app_proxy_port);
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("failed to connect to internal app-proxy-in {addr}"))?;
    let _ = stream.set_nodelay(true);
    let local_port = stream.local_addr()?.port();

    negotiate_userpass(&mut stream, auth_user, password).await?;
    send_request(&mut stream, CMD_CONNECT, target).await?;
    let _bound = read_reply(&mut stream).await?;
    Ok((stream, local_port))
}

/// Active internal SOCKS5 UDP ASSOCIATE session.
pub struct Socks5UdpAssociation {
    pub _control_stream: TcpStream,
    pub relay_addr: SocketAddr,
    pub udp_socket: UdpSocket,
    pub local_udp_port: u16,
}

/// Opens a SOCKS5 UDP ASSOCIATE session against internal `127.0.0.1:{app_proxy_port}`.
pub async fn associate_internal_udp(
    app_proxy_port: u16,
    auth_user: &str,
    password: &str,
) -> Result<Socks5UdpAssociation> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), app_proxy_port);
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("failed to connect to internal app-proxy-in {addr}"))?;
    let _ = stream.set_nodelay(true);
    let proxy_peer_ip = stream.peer_addr()?.ip();

    negotiate_userpass(&mut stream, auth_user, password).await?;

    let bind_target = TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    send_request(&mut stream, CMD_UDP_ASSOCIATE, &bind_target).await?;
    let mut relay_addr = read_reply(&mut stream).await?;
    if relay_addr.ip().is_unspecified() {
        relay_addr.set_ip(proxy_peer_ip);
    }

    let udp_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let local_udp_port = udp_socket.local_addr()?.port();

    Ok(Socks5UdpAssociation {
        _control_stream: stream,
        relay_addr,
        udp_socket,
        local_udp_port,
    })
}

pub fn encode_udp_packet(dst: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    write_target_addr(&mut out, dst)?;
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_udp_packet(packet: &[u8]) -> Result<(SocketAddr, &[u8])> {
    if packet.len() < 4 {
        bail!("SOCKS5 UDP packet too short");
    }
    if packet[2] != 0x00 {
        bail!("fragmented SOCKS5 UDP packets are not supported");
    }
    let atyp = packet[3];
    let (ip, next_pos) = match atyp {
        ATYP_IPV4 => {
            if packet.len() < 10 {
                bail!("truncated SOCKS5 UDP IPv4 header");
            }
            let ip = IpAddr::V4(Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]));
            (ip, 8)
        }
        ATYP_IPV6 => {
            if packet.len() < 22 {
                bail!("truncated SOCKS5 UDP IPv6 header");
            }
            let octets: [u8; 16] = packet[4..20].try_into()?;
            (IpAddr::V6(Ipv6Addr::from(octets)), 20)
        }
        ATYP_DOMAIN => {
            if packet.len() < 5 {
                bail!("truncated SOCKS5 UDP domain length");
            }
            let len = packet[4] as usize;
            if packet.len() < 5 + len + 2 {
                bail!("truncated SOCKS5 UDP domain header");
            }
            let host = std::str::from_utf8(&packet[5..5 + len])?;
            let ip = host
                .parse::<IpAddr>()
                .map_err(|_| anyhow!("SOCKS5 UDP reply used non-IP domain '{host}'"))?;
            (ip, 5 + len)
        }
        other => bail!("invalid SOCKS5 UDP ATYP {other:#x}"),
    };
    let port = u16::from_be_bytes([packet[next_pos], packet[next_pos + 1]]);
    Ok((SocketAddr::new(ip, port), &packet[next_pos + 2..]))
}

async fn negotiate_userpass(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<()> {
    if !username.is_empty() {
        stream
            .write_all(&[SOCKS5_VERSION, 2, AUTH_USERPASS, AUTH_NONE])
            .await?;
    } else {
        stream.write_all(&[SOCKS5_VERSION, 1, AUTH_NONE]).await?;
    }

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != SOCKS5_VERSION {
        bail!("unexpected SOCKS version {:#x}", resp[0]);
    }

    match resp[1] {
        AUTH_NONE => Ok(()),
        AUTH_USERPASS => {
            let user = username.as_bytes();
            let pass = password.as_bytes();
            if user.len() > 255 || pass.len() > 255 {
                bail!("SOCKS5 credentials exceed 255 bytes");
            }
            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01);
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user);
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass);
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                bail!("SOCKS5 auth rejected for user '{username}'");
            }
            Ok(())
        }
        AUTH_NO_ACCEPTABLE => bail!("SOCKS5 server rejected offered auth methods"),
        other => bail!("unsupported SOCKS5 auth method {other:#x}"),
    }
}

async fn send_request(stream: &mut TcpStream, cmd: u8, target: &TargetAddr) -> Result<()> {
    let mut req = Vec::with_capacity(32);
    req.push(SOCKS5_VERSION);
    req.push(cmd);
    req.push(0x00);
    write_target_addr(&mut req, target)?;
    stream.write_all(&req).await?;
    Ok(())
}

fn write_target_addr(buf: &mut Vec<u8>, target: &TargetAddr) -> Result<()> {
    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(v6)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        TargetAddr::Domain(host, port) => {
            let bytes = host.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                bail!("invalid SOCKS5 domain length: {}", bytes.len());
            }
            buf.push(ATYP_DOMAIN);
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

async fn read_reply(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != SOCKS5_VERSION {
        bail!("unexpected SOCKS5 reply version {:#x}", hdr[0]);
    }
    if hdr[1] != 0x00 {
        bail!("SOCKS5 request failed with reply code {:#x}", hdr[1]);
    }
    let ip = match hdr[3] {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            IpAddr::V4(Ipv4Addr::from(addr))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            IpAddr::V6(Ipv6Addr::from(addr))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let s = std::str::from_utf8(&domain)?;
            s.parse::<IpAddr>()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        other => bail!("invalid SOCKS5 reply ATYP {other:#x}"),
    };
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port_bytes)))
}
