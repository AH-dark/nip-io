use std::str::FromStr;

use tokio::net::UdpSocket;
use trust_dns_server::authority::Catalog;
use trust_dns_server::proto::rr::{LowerName, Name};
use trust_dns_server::server::ServerFuture;

use crate::authority::DynamicAuthority;

mod authority;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Options {
    pub dns_domain: String,
    pub ns_domain: String,
    pub host_master_domain: String,
    pub listen: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    #[cfg(feature = "tracing")]
    tracing_subscriber::fmt::init();
    #[cfg(not(feature = "tracing"))]
    pretty_env_logger::init();

    let config = envy::from_env::<Options>()?;
    log::info!("Config: {:?}", config);

    let domain = LowerName::from_str(&config.dns_domain).expect("Invalid domain name");
    let ns_domain = Name::from_str(&config.ns_domain).expect("Invalid NS domain name");
    let host_master_domain =
        Name::from_str(&config.host_master_domain).expect("Invalid host master domain name");

    let mut catalog = Catalog::new();
    let authority = DynamicAuthority::new(domain.clone(), ns_domain, host_master_domain);
    catalog.upsert(domain, Box::new(authority));

    let mut server = ServerFuture::new(catalog);

    let socket = UdpSocket::bind(config.listen.as_ref().unwrap_or(&"0.0.0.0:53".into())).await?;
    server.register_socket(socket);

    log::info!(
        "DNS server running on {}",
        config.listen.unwrap_or("0.0.0.0:53".into())
    );

    server.block_until_done().await?;
    Ok(())
}
