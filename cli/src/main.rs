use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use resolvematrix::{resolution::Resolution, server::MatrixResolver};
use ruma::{
    api::{
        IncomingResponse, OutgoingRequest,
        auth_scheme::NoAuthentication,
        federation::discovery::{
            ServerSigningKeys, get_server_keys,
            get_server_version::{self, v1::Server},
        },
        path_builder::SinglePath,
    },
    exports::http,
    exports::serde_json,
};
use serde::Serialize;
use tracing::warn;

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub(crate) enum OutputFormat {
    Plain,
    Json,
}

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

    /// Set preferred output format.
    #[arg(long, default_value = "plain")]
    format: OutputFormat,
}

#[derive(Serialize)]
pub(crate) struct OutputData {
    resolution: Resolution,
    server_info: Option<Server>,
    server_signing_keys: Option<ServerSigningKeys>,
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

    let mut output_data = OutputData {
        resolution,
        server_info: None,
        server_signing_keys: None,
    };

    let client = RumaClient {
        client: resolver
            .create_client()
            .expect("should be able to create client"),
        base_url: output_data.resolution.base_url(),
    };

    match get_server_info(&client).await {
        Ok((server_info, server_signing_keys)) => {
            output_data.server_info = Some(server_info);
            output_data.server_signing_keys = Some(server_signing_keys);
        }
        Err(error) => {
            warn!(?error, "failed to get server info");
        }
    }

    print_output(&args.server, output_data, args.format);

    Ok(())
}

async fn get_server_info(client: &RumaClient) -> Result<(Server, ServerSigningKeys)> {
    let server_info = client
        .execute_request(get_server_version::v1::Request::new())
        .await
        .with_context(|| "failed to check server version")?;

    if server_info.server.is_none() {
        Err(anyhow::anyhow!("server info is empty"))?
    }

    let signing_keys = client
        .execute_request(get_server_keys::v2::Request::new())
        .await
        .with_context(|| "failed to fetch server signing keys")?
        .server_key
        .deserialize()
        .with_context(|| "failed to deserialize server signing keys")?;

    Ok((server_info.server.unwrap(), signing_keys))
}

fn print_output(server: &String, output_data: OutputData, format: OutputFormat) {
    match format {
        OutputFormat::Plain => {
            println!(
                "Resolved {} to base URL {} using step {}",
                server,
                output_data.resolution.base_url(),
                output_data.resolution.resolution_step
            );
            if output_data.resolution.is_override {
                println!(
                    "    Required SNI/Host override is {}",
                    output_data.resolution.host
                );
            }

            match output_data.server_info {
                Some(Server {
                    name: Some(name),
                    version: Some(version),
                    ..
                }) => println!("Server is {name} version {version}"),
                Some(Server {
                    name: Some(name),
                    version: None,
                    ..
                }) => println!("Server is {name} (no version provided)"),
                Some(Server {
                    name: None,
                    version: Some(version),
                    ..
                }) => println!("Server is version {version} (no name provided, for some reason)"),
                None => println!("Server is unreachable"),
                _ => println!("Server is reachable but did not provide its name or version"),
            }

            match output_data.server_signing_keys {
                Some(signing_keys) => {
                    println!("Server has signing keys:");
                    for (version, key) in signing_keys.verify_keys {
                        println!("- {version}: {}", key.key);
                    }
                }
                None => (),
            }
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&output_data)
                .expect("should be able to serialize to json");
            println!("{json}")
        }
    }
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
