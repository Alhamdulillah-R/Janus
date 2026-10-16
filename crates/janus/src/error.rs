/**
 * Errors surfaced by the Janus client.
 */
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid profile: {0}")]
    Profile(String),

    #[error("tls: {0}")]
    Tls(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("http2: {0}")]
    Http2(#[from] janus_h2::Error),

    #[error("http: {0}")]
    Http(#[from] http::Error),

    #[error("invalid url: {0}")]
    Url(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("proxy: {0}")]
    Proxy(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("connect timeout: {0}")]
    ConnectTimeout(String),

    #[error("read timeout: {0}")]
    ReadTimeout(String),

    #[error("connect: {0}")]
    Connect(String),

    /// the connection went away after the request was (partly) sent
    #[error("connection closed: {0}")]
    Disconnected(String),

    #[error("response body: {0}")]
    Body(String),

    #[error("too many redirects ({0})")]
    TooManyRedirects(usize),

    #[error("decode: {0}")]
    Decode(String),
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::Tls(e.to_string())
    }
}

impl From<openssl::ssl::Error> for Error {
    fn from(e: openssl::ssl::Error) -> Self {
        Error::Tls(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
