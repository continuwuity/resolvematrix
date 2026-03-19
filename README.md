# `resolvematrix`

[![Dependency status](https://deps.rs/repo/gitea/forgejo.ellis.link/continuwuation/resolvematrix/status.svg)](https://deps.rs/repo/gitea/forgejo.ellis.link/continuwuation/resolvematrix)
[![crates.io](https://img.shields.io/crates/v/resolvematrix)](https://crates.io/crates/resolvematrix)
[![docs.rs](https://img.shields.io/docsrs/resolvematrix)](https://docs.rs/resolvematrix)


[![forgejo.ellis.link](https://img.shields.io/badge/Ellis%20Git-main-green?style=flat&logo=forgejo&labelColor=fff)](https://forgejo.ellis.link/continuwuation/resolvematrix) [![Issues](https://forgejo.ellis.link/continuwuation/resolvematrix/badges/issues/open.svg?style=flat)](https://forgejo.ellis.link/continuwuation/resolvematrix/issues?state=open) [![Pull Requests](https://forgejo.ellis.link/continuwuation/resolvematrix/badges/pulls/open.svg?style=flat)](https://forgejo.ellis.link/continuwuation/resolvematrix/pulls?state=open)

[![GitHub](https://img.shields.io/badge/GitHub-mirror-blue?style=flat&logo=github&labelColor=fff&logoColor=24292f)](https://github.com/continuwuity/resolvematrix)

`resolvematrix` is a Rust library providing the ability to resolve Matrix server-to-server endpoints from the server name.
It conforms to the [Server Discovery section in the Matrix specification](https://spec.matrix.org/v1.15/server-server-api/#server-discovery).

The library is tested against the resolvematrix.dev suite and live domains.

This library depends on hickory-resolver, reqwest, serde and (indirectly) tokio.

## Usage

`cargo add resolvematrix`

### Example

```rust
use resolvematrix::server::MatrixResolver;

// Create a new resolver
let resolver = Arc::new(MatrixResolver::new()?);

// Resolve a server name
let server_name = "matrix.org";
let resolution = resolver.resolve_server(server_name).await?;
eprintln!("Resolved server: {resolution:?}");

let client = resolver.create_client().unwrap();
let url = format!("{}/_matrix/federation/v1/version", resolution.base_url());
let response = client.get(&url).send().await;

```

License: MPL-2.0
