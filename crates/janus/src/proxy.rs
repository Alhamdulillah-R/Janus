use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::error::{Error, Result};

/**
 * Upstream proxy: HTTP (CONNECT for https, absolute-form for http) or SOCKS5.
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    /// SOCKS5 with the target name resolved locally
    Socks5,
    /// SOCKS5 with the target name resolved by the proxy
    Socks5h,
}

impl Proxy {
    /**
     * Parse `http://user:pass@host:port`, `socks5://...` or `socks5h://...`.
     */
    pub fn parse(text: &str) -> Result<Proxy> {
        let url = Url::parse(text).map_err(|e| Error::Proxy(format!("bad proxy url {text}: {e}")))?;
        let kind = match url.scheme() {
            "http" => ProxyKind::Http,
            "socks5" => ProxyKind::Socks5,
            "socks5h" => ProxyKind::Socks5h,
            other => {
                return Err(Error::Proxy(format!(
                    "unsupported proxy scheme {other} (http, socks5 and socks5h are supported)"
                )));
            }
        };
        let host = url
            .host_str()
            .ok_or_else(|| Error::Proxy(format!("proxy url has no host: {text}")))?
            .trim_matches(['[', ']'])
            .to_string();
        let port = url.port().unwrap_or(match kind {
            ProxyKind::Http => 8080,
            _ => 1080,
        });
        let auth = if url.username().is_empty() {
            None
        } else {
            let user = percent_decode(url.username());
            let pass = percent_decode(url.password().unwrap_or(""));
            Some((user, pass))
        };

        Ok(Proxy { kind, host, port, auth })
    }

    /**
     * Value for a Proxy-Authorization header, when credentials are present.
     */
    pub fn authorization(&self) -> Option<String> {
        let (user, pass) = self.auth.as_ref()?;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        Some(format!("Basic {token}"))
    }

    /**
     * Open a TCP tunnel to host:port through this proxy.
     */
    pub async fn tunnel(&self, host: &str, port: u16) -> Result<TcpStream> {
        match self.kind {
            ProxyKind::Http => self.http_connect(host, port).await,
            ProxyKind::Socks5 => {
                let addr = tokio::net::lookup_host((host, port))
                    .await?
                    .next()
                    .ok_or_else(|| Error::Proxy(format!("cannot resolve {host}")))?;
                self.socks5_connect(&addr.ip().to_string(), port).await
            }
            ProxyKind::Socks5h => self.socks5_connect(host, port).await,
        }
    }

    /**
     * Plain TCP connection to the proxy itself (absolute-form HTTP requests).
     */
    pub async fn connect_direct(&self) -> Result<TcpStream> {
        let stream = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| Error::Proxy(format!("cannot reach proxy {}:{}: {e}", self.host, self.port)))?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    async fn http_connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        let mut stream = self.connect_direct().await?;
        let authority = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");

        if let Some(auth) = self.authorization() {
            head.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        }
        head.push_str("Proxy-Connection: keep-alive\r\n\r\n");
        stream.write_all(head.as_bytes()).await?;

        let mut buf = Vec::with_capacity(1024);
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await? == 0 {
                return Err(Error::Proxy("proxy closed during CONNECT".into()));
            }
            buf.push(byte[0]);
            if buf.len() > 64 * 1024 {
                return Err(Error::Proxy("CONNECT response head too large".into()));
            }
        }

        let status_line = String::from_utf8_lossy(&buf);
        let status = status_line.split_whitespace().nth(1).unwrap_or("");
        if !status.starts_with('2') {
            let first = status_line.lines().next().unwrap_or("").to_string();
            return Err(Error::Proxy(format!("CONNECT {authority} refused: {first}")));
        }
        Ok(stream)
    }

    async fn socks5_connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        let proxy = (self.host.as_str(), self.port);
        let target = (host, port);

        let stream = match &self.auth {
            Some((user, pass)) => tokio_socks::tcp::Socks5Stream::connect_with_password(proxy, target, user, pass).await,
            None => tokio_socks::tcp::Socks5Stream::connect(proxy, target).await,
        }
        .map_err(|e| Error::Proxy(format!("socks5 connect to {host}:{port} failed: {e}")))?;

        let stream = stream.into_inner();
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
