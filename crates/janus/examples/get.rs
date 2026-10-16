//! Fetch URLs with a built-in profile and print status, protocol and body size.
//!
//! usage: get <profile> <url> [url...]

use janus::{Client, ClientConfig, Profile, Request};
use http::Method;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let profile = Profile::named(args.get(1).map(String::as_str).unwrap_or("chrome155"))?;
    let client = Client::new(ClientConfig::new(profile))?;

    for url in &args[2..] {
        let response = client.execute(Request::new(Method::GET, url)?).await?;

        println!(
            "{} {:?} {} bytes={} history={:?} elapsed={:?}",
            response.status,
            response.version,
            response.url,
            response.body.len(),
            response.history,
            response.elapsed
        );
        for (name, value) in &response.headers {
            println!("  {name}: {value}");
        }
        if std::env::var_os("JANUS_PRINT_BODY").is_some() {
            println!("{}", String::from_utf8_lossy(&response.body));
        }
    }
    Ok(())
}
