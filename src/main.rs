use std::env;
use std::str::FromStr;

use tokio::net::UdpSocket;
use trust_dns_server::authority::Catalog;
use trust_dns_server::proto::rr::LowerName;
use trust_dns_server::server::ServerFuture;

use crate::authority::DynamicAuthority;

mod authority;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "tracing")]
    tracing_subscriber::fmt::init();
    #[cfg(not(feature = "tracing"))]
    pretty_env_logger::init();

    let name = LowerName::from_str(
        env::var("DNS_DOMAIN")
            .expect("`DNS_DOMAIN` environment variable not set")
            .as_str(),
    )
    .expect("Invalid domain name");

    let mut catalog = Catalog::new();
    let authority = DynamicAuthority::new(name.clone());
    catalog.upsert(name.clone(), Box::new(authority));

    let mut server = ServerFuture::new(catalog);

    let socket = UdpSocket::bind("0.0.0.0:53").await?;
    server.register_socket(socket);

    log::info!("DNS server running on 0.0.0.0:53");

    server.block_until_done().await?;
    Ok(())
}
