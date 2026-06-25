# `resolvematrix`

[![Dependency status](https://deps.rs/repo/gitea/forgejo.ellis.link/continuwuation/resolvematrix/status.svg)](https://deps.rs/repo/gitea/forgejo.ellis.link/continuwuation/resolvematrix)
[![crates.io](https://img.shields.io/crates/v/resolvematrix)](https://crates.io/crates/resolvematrix)
[![docs.rs](https://img.shields.io/docsrs/resolvematrix)](https://docs.rs/resolvematrix)
[![MPL-2.0 license](https://img.shields.io/crates/l/resolvematrix)](https://forgejo.ellis.link/continuwuation/resolvematrix/src/branch/main/LICENSE)

[![forgejo.ellis.link](https://img.shields.io/badge/Ellis%20Git-main-green?style=flat&logo=forgejo&labelColor=fff)](https://forgejo.ellis.link/continuwuation/resolvematrix) [![Issues](https://forgejo.ellis.link/continuwuation/resolvematrix/badges/issues/open.svg?style=flat)](https://forgejo.ellis.link/continuwuation/resolvematrix/issues?state=open) [![Pull Requests](https://forgejo.ellis.link/continuwuation/resolvematrix/badges/pulls/open.svg?style=flat)](https://forgejo.ellis.link/continuwuation/resolvematrix/pulls?state=open)
[![GitHub mirror](https://img.shields.io/badge/GitHub-mirror-blue?style=flat&logo=github&labelColor=fff&logoColor=24292f)](https://github.com/continuwuity/resolvematrix)

`resolvematrix` is a Rust library providing the ability to resolve Matrix server-to-server endpoints from the server name.
It conforms to the [Server discovery chapter of the Matrix specification](https://spec.matrix.org/v1.18/server-server-api/#resolving-server-names).

The library is tested against the https://resolvematrix.dev suite and other live Matrix servers.

This library depends on `hickory-resolver`, `reqwest`, `serde` and (indirectly) `tokio`.

## Usage

`cargo add resolvematrix`

### Example

```rust
use resolvematrix::server::{MatrixResolver, MatrixResolverBuilder};

// Create a new resolver
let resolver = Arc::new(MatrixResolver::new()?);
// Or to use custom options:
// MatrixResolverBuilder::new().cache_ttl(Duration::from_secs(10)).build()?

// Resolve a server name
let server_name = "matrix.org";
let resolution = resolver.resolve_server(server_name).await?;
eprintln!("Resolved server: {resolution:?}");

let client = resolver.create_client().unwrap();
let url = format!("{}/_matrix/federation/v1/version", resolution.base_url());
let response = client.get(&url).send().await;

```

For more examples, see the [examples](https://forgejo.ellis.link/continuwuation/resolvematrix/src/branch/main/examples) directory.

## Contributing

Resolvematrix is part of the [Continuwuity](https://continuwuity.org) project. Please see the
[Contributing guide](https://continuwuity.org/development/contributing) before submitting a pull request.

## Code of Conduct

Contributors are expected to follow the [Continuwuity Community Guidelines](https://continuwuity.org/community/guidelines).
