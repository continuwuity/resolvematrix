//! `resolvematrix` is a Rust library providing the ability to resolve Matrix server-to-server endpoints from the server name.
//! It conforms to the [Server Discovery section in the Matrix specification](https://spec.matrix.org/v1.15/server-server-api/#server-discovery).
//!
//! The library is tested against the resolvematrix.dev suite and live domains.
//!
//! This library depends on hickory-resolver, reqwest, serde and (indirectly) tokio.
//!
//! # Usage
//!
//! `cargo add resolvematrix`
//!
//! ## Example
//!
//! ```rust,no_run
//! use resolvematrix::server::MatrixResolver;
//! # use std::sync::Arc;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a new resolver
//! let resolver = Arc::new(MatrixResolver::new().await?);
//!
//! // Resolve a server name
//! let server_name = "matrix.org";
//! let resolution = resolver.resolve_server(server_name).await?;
//! eprintln!("Resolved server: {resolution:?}");
//!
//! let client = resolver.create_client().unwrap();
//! let url = format!("{}/_matrix/federation/v1/version", resolution.base_url());
//! let response = client.get(&url).send().await;
//!
//! Ok(())
//! # }
//! ```

#[cfg(feature = "server")]
pub mod server;
