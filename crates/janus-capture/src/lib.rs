//! Browser capture for Janus: record a ClientHello and HTTP/2 connection, build a profile from them.

pub mod builder;
pub mod clienthello;
pub mod h2frames;
pub mod server;

pub use builder::{Built, ProfileBuilder};
pub use clienthello::{ClientHello, is_grease, read_client_hello};
pub use server::{Capture, CaptureConfig, CaptureServer, CaptureView, Snapshot};
