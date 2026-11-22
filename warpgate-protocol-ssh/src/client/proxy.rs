//! Egress proxy support for the first hop of an SSH target chain.
//!
//! Warpgate dials SSH targets directly. A target that is only reachable from
//! another network position (an egress VPS, a jump box on a different
//! continent) cannot be reached at all, and `jump_host` does not help because
//! it too is dialled directly. This module opens the TCP connection to the
//! first hop through a SOCKS5 or HTTP `CONNECT` proxy instead, after which the
//! SSH handshake runs unchanged over the tunnel.

use std::io;
use std::net::IpAddr;

use data_encoding::BASE64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use warpgate_common::{SshProxyKind, SshProxyOptions};

use super::ConnectionError;

/// How long the proxy may take to accept the TCP connection and answer.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Everything needed to reach the proxy, with credentials already resolved.
pub struct ResolvedProxy {
    pub kind: SshProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub skip_private_networks: bool,
}

impl ResolvedProxy {
    /// Turn the stored options into a descriptor, applying the scheme's default
    /// port and rejecting unusable addresses early.
    pub fn parse(
        options: &SshProxyOptions,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<Option<Self>, ConnectionError> {
        let default_port = match options.kind {
            SshProxyKind::None => return Ok(None),
            SshProxyKind::Socks5 => 1080,
            SshProxyKind::HttpConnect => 3128,
        };
        let raw = options.address.trim();
        if raw.is_empty() {
            return Err(ConnectionError::Proxy(
                "Proxy is enabled but its address is empty".to_string(),
            ));
        }
        let (host, port) = split_host_port(raw).ok_or_else(|| {
            ConnectionError::Proxy(format!("Cannot parse proxy address {raw:?}"))
        })?;
        if host.is_empty() {
            return Err(ConnectionError::Proxy(format!(
                "Proxy address {raw:?} has no host part"
            )));
        }
        Ok(Some(Self {
            kind: options.kind,
            host,
            port: port.unwrap_or(default_port),
            username,
            password,
            skip_private_networks: options.skip_private_networks,
        }))
    }

    /// Whether the target must bypass the proxy.
    ///
    /// Checked against the literal host when it is an IP, and against every
    /// resolved address otherwise, so a DNS name that points at the LAN is not
    /// sent to a remote proxy.
    async fn bypasses(&self, host: &str, port: u16) -> bool {
        if !self.skip_private_networks {
            return false;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return is_private(ip);
        }
        match tokio::net::lookup_host((host, port)).await {
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.collect();
                !addrs.is_empty() && addrs.iter().all(|a| is_private(a.ip()))
            }
            Err(_) => false,
        }
    }
}

/// Loopback, private, link-local, CGNAT and unspecified addresses.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // 100.64.0.0/10, carrier-grade NAT (also Tailscale's range)
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique local addresses, fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local, fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some_and(|v4| is_private(IpAddr::V4(v4)))
        }
    }
}

/// Split `host`, `host:port`, `[v6]` or `[v6]:port`.
fn split_host_port(raw: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match raw.rsplit_once(':') {
        // A single colon means host:port. More than one without brackets is a
        // bare IPv6 literal, which cannot carry a port here.
        Some((host, port)) if !host.contains(':') => {
            Some((host.to_string(), Some(port.parse().ok()?)))
        }
        Some(_) => Some((raw.to_string(), None)),
        None => Some((raw.to_string(), None)),
    }
}

/// Connect to `host:port` for the first SSH hop.
///
/// Without a proxy this is a plain `TcpStream::connect`, which tries every
/// resolved address in turn. With one, the TCP connection goes to the proxy and
/// the SSH handshake later runs over the tunnel; the proxy resolves the target
/// hostname, which is the point of sending the connection there.
pub async fn connect_first_hop(
    proxy: Option<&ResolvedProxy>,
    host: &str,
    port: u16,
) -> Result<TcpStream, ConnectionError> {
    let Some(proxy) = proxy else {
        return direct(host, port).await;
    };

    if proxy.bypasses(host, port).await {
        tracing::info!(
            host = %host,
            port = port,
            "Target is on a private network; skipping the configured proxy"
        );
        return direct(host, port).await;
    }

    let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
    tracing::info!(
        proxy = %proxy_addr,
        kind = ?proxy.kind,
        host = %host,
        port = port,
        "Connecting to the target through a proxy"
    );
    let mut stream = TcpStream::connect(&proxy_addr).await.map_err(|e| {
        ConnectionError::Proxy(format!("Cannot reach proxy {proxy_addr}: {e}"))
    })?;
    stream.set_nodelay(true).ok();

    match proxy.kind {
        SshProxyKind::None => unreachable!("filtered above"),
        SshProxyKind::Socks5 => socks5_handshake(&mut stream, proxy, host, port).await?,
        SshProxyKind::HttpConnect => http_connect_handshake(&mut stream, proxy, host, port).await?,
    }

    Ok(stream)
}

async fn direct(host: &str, port: u16) -> Result<TcpStream, ConnectionError> {
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(ConnectionError::Io)?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// SOCKS5 per RFC 1928 / RFC 1929, with the hostname sent to the proxy
/// (`ATYP=DOMAINNAME`) so that DNS resolution happens on the proxy side.
async fn socks5_handshake(
    stream: &mut TcpStream,
    proxy: &ResolvedProxy,
    host: &str,
    port: u16,
) -> Result<(), ConnectionError> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        socks5_handshake_inner(stream, proxy, host, port),
    )
    .await
    .map_err(|_| ConnectionError::Proxy("SOCKS5 handshake timed out".to_string()))?
}

async fn socks5_handshake_inner(
    stream: &mut TcpStream,
    proxy: &ResolvedProxy,
    host: &str,
    port: u16,
) -> Result<(), ConnectionError> {
    let want_auth = proxy.username.is_some() || proxy.password.is_some();

    // Greeting: offer no-auth and, when credentials are configured, username/password.
    let methods: &[u8] = if want_auth { &[0x00, 0x02] } else { &[0x00] };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await.map_err(io_proxy)?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.map_err(io_proxy)?;
    if reply[0] != 0x05 {
        return Err(ConnectionError::Proxy(format!(
            "Proxy did not answer with SOCKS5 (got version {})",
            reply[0]
        )));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            if !want_auth {
                return Err(ConnectionError::Proxy(
                    "Proxy requires username/password authentication, but none is configured"
                        .to_string(),
                ));
            }
            let user = proxy.username.clone().unwrap_or_default();
            let pass = proxy.password.clone().unwrap_or_default();
            if user.len() > 255 || pass.len() > 255 {
                return Err(ConnectionError::Proxy(
                    "SOCKS5 username and password must be at most 255 bytes".to_string(),
                ));
            }
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await.map_err(io_proxy)?;
            let mut auth_reply = [0u8; 2];
            stream.read_exact(&mut auth_reply).await.map_err(io_proxy)?;
            if auth_reply[1] != 0x00 {
                return Err(ConnectionError::Proxy(
                    "SOCKS5 proxy rejected the configured credentials".to_string(),
                ));
            }
        }
        0xFF => {
            return Err(ConnectionError::Proxy(
                "SOCKS5 proxy accepted none of the offered authentication methods".to_string(),
            ));
        }
        other => {
            return Err(ConnectionError::Proxy(format!(
                "SOCKS5 proxy chose unsupported authentication method {other:#04x}"
            )));
        }
    }

    // CONNECT request, hostname-typed so the proxy resolves it.
    if host.len() > 255 {
        return Err(ConnectionError::Proxy(
            "Target hostname is too long for SOCKS5".to_string(),
        ));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.map_err(io_proxy)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io_proxy)?;
    if head[0] != 0x05 {
        return Err(ConnectionError::Proxy(
            "SOCKS5 proxy sent a malformed reply".to_string(),
        ));
    }
    if head[1] != 0x00 {
        return Err(ConnectionError::Proxy(format!(
            "SOCKS5 proxy refused to connect to {host}:{port}: {}",
            socks5_error(head[1])
        )));
    }
    // Drain the bound address so the stream is positioned at the tunnel payload.
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 4 + 2];
            stream.read_exact(&mut skip).await.map_err(io_proxy)?;
        }
        0x04 => {
            let mut skip = [0u8; 16 + 2];
            stream.read_exact(&mut skip).await.map_err(io_proxy)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io_proxy)?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await.map_err(io_proxy)?;
        }
        atyp => {
            return Err(ConnectionError::Proxy(format!(
                "SOCKS5 proxy replied with unknown address type {atyp:#04x}"
            )));
        }
    }
    Ok(())
}

const fn socks5_error(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

/// HTTP `CONNECT` per RFC 7231 §4.3.6.
async fn http_connect_handshake(
    stream: &mut TcpStream,
    proxy: &ResolvedProxy,
    host: &str,
    port: u16,
) -> Result<(), ConnectionError> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        http_connect_handshake_inner(stream, proxy, host, port),
    )
    .await
    .map_err(|_| ConnectionError::Proxy("HTTP CONNECT handshake timed out".to_string()))?
}

async fn http_connect_handshake_inner(
    stream: &mut TcpStream,
    proxy: &ResolvedProxy,
    host: &str,
    port: u16,
) -> Result<(), ConnectionError> {
    // IPv6 literals must stay bracketed in the request target.
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let (Some(user), Some(pass)) = (&proxy.username, &proxy.password) {
        let token = BASE64.encode(format!("{user}:{pass}").as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(io_proxy)?;

    // Read header bytes one at a time so nothing past the blank line is
    // consumed: the tunnel payload starts immediately after it.
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err(ConnectionError::Proxy(
                "HTTP CONNECT proxy sent an oversized response".to_string(),
            ));
        }
        stream.read_exact(&mut byte).await.map_err(io_proxy)?;
        head.push(byte[0]);
    }

    let status_line = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            ConnectionError::Proxy(format!("Malformed proxy response: {status_line:?}"))
        })?;
    if !(200..300).contains(&status) {
        return Err(ConnectionError::Proxy(format!(
            "HTTP CONNECT proxy refused to connect to {authority}: {status_line}"
        )));
    }
    Ok(())
}

fn io_proxy(error: io::Error) -> ConnectionError {
    ConnectionError::Proxy(format!("Proxy handshake failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_host_and_port() {
        assert_eq!(
            split_host_port("proxy.local"),
            Some(("proxy.local".into(), None))
        );
        assert_eq!(
            split_host_port("proxy.local:1080"),
            Some(("proxy.local".into(), Some(1080)))
        );
        assert_eq!(
            split_host_port("[::1]:1080"),
            Some(("::1".into(), Some(1080)))
        );
        assert_eq!(split_host_port("[::1]"), Some(("::1".into(), None)));
        assert_eq!(split_host_port("::1"), Some(("::1".into(), None)));
    }

    #[test]
    fn detects_private_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.9.6",
            "172.16.0.1",
            "169.254.1.1",
            "100.100.88.9",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(is_private(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "9.9.9.9"] {
            assert!(!is_private(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
    }

    #[test]
    fn default_ports_follow_the_scheme() {
        let socks = SshProxyOptions {
            kind: SshProxyKind::Socks5,
            address: "127.0.0.1".into(),
            ..Default::default()
        };
        let resolved = ResolvedProxy::parse(&socks, None, None).unwrap().unwrap();
        assert_eq!(resolved.port, 1080);

        let http = SshProxyOptions {
            kind: SshProxyKind::HttpConnect,
            address: "127.0.0.1".into(),
            ..Default::default()
        };
        let resolved = ResolvedProxy::parse(&http, None, None).unwrap().unwrap();
        assert_eq!(resolved.port, 3128);
    }

    #[test]
    fn explicit_port_wins() {
        let options = SshProxyOptions {
            kind: SshProxyKind::Socks5,
            address: "127.0.0.1:30171".into(),
            ..Default::default()
        };
        let resolved = ResolvedProxy::parse(&options, None, None).unwrap().unwrap();
        assert_eq!(resolved.port, 30171);
    }

    #[test]
    fn no_proxy_means_no_proxy() {
        assert!(
            ResolvedProxy::parse(&SshProxyOptions::default(), None, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn empty_address_is_rejected() {
        let options = SshProxyOptions {
            kind: SshProxyKind::Socks5,
            address: "  ".into(),
            ..Default::default()
        };
        assert!(ResolvedProxy::parse(&options, None, None).is_err());
    }
}