//! Janus: an HTTP client whose TLS ClientHello and HTTP/2 framing are specified exactly.

pub mod body;
pub mod client;
pub mod decode;
pub mod error;
pub mod http1;
pub mod http2;
pub mod profile;
mod profile_json;
pub mod proxy;
pub mod tls;
pub mod upload;

pub use body::Body;
pub use client::{Client, ClientConfig, HttpVersion, ProxyChoice, Request, Response, StreamResponse};
pub use decode::StreamDecoder;
pub use error::{Error, Result};
pub use http2::{H2Connection, HpackStyle, Http2Profile, PriorityMode, StreamPriority};
pub use profile::Profile;
pub use profile_json::{indexing_from, indexing_name};
pub use proxy::Proxy;
pub use tls::{ClientCert, EchGrease, GREASE, TlsConnector, TlsMode, TlsProfile, Verify};
pub use upload::{Upload, UploadSender};
pub use janus_h2::{HpackPolicy, Huffman, Indexing};
