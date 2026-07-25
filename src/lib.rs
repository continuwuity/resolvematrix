//! `resolvematrix` is a Rust library providing the ability to resolve Matrix server-to-server endpoints from the server name.
//! It conforms to the [Server discovery chapter of the Matrix specification](https://spec.matrix.org/v1.18/server-server-api/#resolving-server-names).
//!
//! The library is tested against the https://resolvematrix.dev suite and other live Matrix servers.
//!
//! This library depends on `hickory-resolver`, `reqwest`, `serde` and (indirectly) `tokio`.
//!
//! # Usage
//!
//! `cargo add resolvematrix`
//!
//! ## Example
//!
//! ```rust,no_run
//! use resolvematrix::server::{MatrixResolver, MatrixResolverBuilder};
//! # use std::sync::Arc;
//! # use std::time::Duration;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! // Create a new resolver
//! let resolver = Arc::new(MatrixResolver::new()?);
//! // Or to use custom options:
//! // MatrixResolverBuilder::new().cache_ttl(Duration::from_secs(10)).build()?
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
//! # Ok(())
//! # }
//! ```
//!
//! For more examples, see the [examples](https://forgejo.ellis.link/continuwuation/resolvematrix/src/branch/main/examples) directory.

pub mod cache;
pub mod error;
pub mod resolution;
pub mod server;
