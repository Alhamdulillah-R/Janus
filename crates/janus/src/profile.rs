use crate::error::{Error, Result};
use crate::http2::Http2Profile;
use crate::tls::TlsProfile;

/**
 * A complete client identity: ClientHello, HTTP/2 framing and request header order; header values come from the caller.
 */
#[derive(Clone, Debug)]
pub struct Profile {
    pub name: String,
    pub tls: TlsProfile,
    pub http2: Http2Profile,
    /// lowercase header names in wire order; unlisted headers go last in insertion order
    pub header_order: Vec<String>,
}

impl Profile {
    /**
     * Look up a built-in profile by name.
     */
    pub fn named(name: &str) -> Result<Profile> {
        match name {
            "chrome155" | "chrome" => Ok(Profile::chrome155()),
            _ => Err(Error::Profile(format!("unknown profile {name}"))),
        }
    }

    /**
     * Chrome 155 on Windows, header order of a top-level navigation.
     */
    pub fn chrome155() -> Profile {
        Profile {
            name: "chrome155".into(),
            tls: TlsProfile::chrome155(),
            http2: Http2Profile::chrome155(),
            header_order: names(&[
                "host",
                "connection",
                "content-length",
                "cache-control",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "origin",
                "content-type",
                "upgrade-insecure-requests",
                "user-agent",
                "accept",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-user",
                "sec-fetch-dest",
                "referer",
                "accept-encoding",
                "accept-language",
                "cookie",
                "priority",
            ]),
        }
    }
}

fn names(items: &[&str]) -> Vec<String> {
    items.iter().map(|n| n.to_string()).collect()
}

/**
 * Merge automatic and user headers, then order them.
 *
 * A user header replaces the automatic one of the same name, repeated user headers are all sent,
 * and a `None` value deletes the header.
 */
pub fn assemble_headers(
    automatic: &[(String, String)],
    user: &[(String, Option<String>)],
    order: &[String],
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = automatic.to_vec();
    let mut given: Vec<(String, String)> = Vec::with_capacity(user.len());

    for (name, value) in user {
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        match value {
            Some(v) => given.push((name.clone(), v.clone())),
            None => given.retain(|(n, _)| !n.eq_ignore_ascii_case(name)),
        }
    }
    headers.extend(given);

    let rank = |name: &str| {
        order
            .iter()
            .position(|o| o.eq_ignore_ascii_case(name))
            .unwrap_or(order.len())
    };
    headers.sort_by_key(|(n, _)| rank(n));
    headers
}
