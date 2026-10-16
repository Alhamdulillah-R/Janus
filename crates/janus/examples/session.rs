//! Exercise pooling, the Chrome priority tree and TLS session resumption against h2probe.
//!
//! usage: session <base-url> [tag]

use http::Method;
use janus::client::user_headers;
use janus::{Client, ClientConfig, Profile, Request};

/**
 * GET `path` with the given Priority header value.
 */
async fn fetch(client: &Client, url: &str, priority: &str) -> Result<String, janus::Error> {
    let mut request = Request::new(Method::GET, url)?;
    request.headers = user_headers(&[("priority", priority)]);

    let response = client.execute(request).await?;
    Ok(format!(
        "{} {:?} resumed={} bytes={}",
        response.status,
        response.version,
        response.tls_resumed,
        response.body.len()
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).map(String::as_str).unwrap_or("https://169-58-190-113.sslip.io:80");
    let tag = args.get(2).map(String::as_str).unwrap_or("janus-session");
    let client = Client::new(ClientConfig::new(Profile::chrome155()))?;

    let first = fetch(&client, &format!("{base}/?tag={tag}-1"), "u=0, i").await?;
    println!("first      {first}");

    let url_a = format!("{base}/api/get?tag={tag}-a");
    let url_b = format!("{base}/api/get?tag={tag}-b");
    let url_c = format!("{base}/api/get?tag={tag}-c");
    let (a, b, c) = tokio::join!(
        fetch(&client, &url_a, "u=0"),
        fetch(&client, &url_b, "u=2"),
        fetch(&client, &url_c, "u=1, i"),
    );
    println!("concurrent {:?} {:?} {:?}", a?, b?, c?);

    // new connection, same client: the ticket from the first handshake should be used
    client.close();
    let resumed = fetch(&client, &format!("{base}/?tag={tag}-resumed"), "u=0, i").await?;
    println!("resumed    {resumed}");

    client.close();
    let again = fetch(&client, &format!("{base}/?tag={tag}-resumed-2"), "u=0, i").await?;
    println!("again      {again}");
    Ok(())
}
