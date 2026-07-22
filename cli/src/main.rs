use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use resolvematrix::server::MatrixResolver;
use ruma::{
    api::{
        IncomingResponse, OutgoingRequest,
        auth_scheme::NoAuthentication,
        federation::discovery::{
            get_server_keys,
            get_server_version::{self, v1::Server},
        },
        path_builder::SinglePath,
    },
    exports::http,
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The Matrix server name to resolve.
    server: String,

    /// Accept invalid TLS certificates, such as self-signed ones.
    ///
    /// Only useful for testing; no production Matrix homeserver will
    /// accept such a certificate for federation.
    #[arg(long)]
    allow_invalid_tls_certificates: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let resolver = Arc::new(
        MatrixResolver::builder()
            .dangerous_tls_accept_invalid_certs(args.allow_invalid_tls_certificates)
            .build()
            .expect("should be able to build resolver"),
    );

    let resolution = resolver
        .resolve_server(&args.server)
        .await
        .with_context(|| format!("failed to resolve {}", args.server))?;

    println!(
        "Resolved {} to base URL {} using step {}",
        args.server,
        resolution.base_url(),
        resolution.resolution_step
    );
    if resolution.is_override {
        println!("    Required SNI/Host override is {}", resolution.host);
    }

    let client = RumaClient {
        client: resolver
            .create_client()
            .expect("should be able to create client"),
        base_url: resolution.base_url(),
    };

    let federation_version = client
        .execute_request(get_server_version::v1::Request::new())
        .await
        .with_context(|| "failed to check server version")?;

    match federation_version.server {
        Some(Server {
            name: Some(name),
            version: Some(version),
            ..
        }) => {
            println!("Server is {name} version {version}");
        }
        Some(Server {
            name: Some(name),
            version: None,
            ..
        }) => {
            println!("Server is {name} (no version provided)");
        }
        Some(Server {
            name: None,
            version: Some(version),
            ..
        }) => {
            println!("Server is version {version} (no name provided, for some reason)");
        }
        _ => {
            println!("Server is reachable but did not provide its version");
        }
    }

    let signing_keys = client
        .execute_request(get_server_keys::v2::Request::new())
        .await
        .with_context(|| "failed to fetch server signing keys")?
        .server_key
        .deserialize()
        .with_context(|| "failed to deserialize server signing keys")?;

    for (version, key) in &signing_keys.verify_keys {
        println!("Server key {version} is {}", key.key);
    }

    Ok(())
}

struct RumaClient {
    client: reqwest::Client,
    base_url: String,
}

impl RumaClient {
    async fn execute_request<R>(&self, request: R) -> Result<R::IncomingResponse>
    where
        R: OutgoingRequest<Authentication = NoAuthentication, PathBuilder = SinglePath>,
        <R as OutgoingRequest>::EndpointError: std::marker::Sync,
    {
        let mut response = self
            .client
            .execute(
                request
                    .try_into_http_request::<Vec<u8>>(&self.base_url, (), ())
                    .expect("should be able to create request")
                    .try_into()
                    .expect("request should be valid"),
            )
            .await?;

        let mut http_builder = http::Response::builder()
            .status(response.status())
            .version(response.version());

        std::mem::swap(
            http_builder.headers_mut().expect("builder should be okay"),
            response.headers_mut(),
        );

        R::IncomingResponse::try_from_http_response(
            http_builder
                .body(
                    response
                        .bytes()
                        .await
                        .with_context(|| "error reading response")?,
                )
                .expect("should be able to build response"),
        )
        .with_context(|| "failed to deserialize response")
    }
}
