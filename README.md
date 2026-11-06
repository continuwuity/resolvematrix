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

This repository includes a minimal implementation of the library in the form of a command-line tool.

## Usage

### Library

`cargo add resolvematrix`

#### Example

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

### CLI

The CLI is currently available as follows:

#### RPM

`resolvematrix` is available as an RPM package through Terra for all of the same Linux distributions as described on [Continuwuity's RPM installation page](https://continuwuity.org/deploying/rpm.html), except for SUSE.

To install, follow [Terra's directions for adding the Terra repo on your distribution](https://docs.terrapkg.com/usage/installing/) (note that no subrepos are required for this package), then run `sudo dnf install resolvematrix`.

#### Nix

`resolvematrix` is available from Nixpkgs. To obtain and run the CLI through Nix, you can:

- Run `nix run nixpkgs#resolvematrix`, or
- Add `pkgs.resolvematrix` to your system configuration

#### Other platforms

`resolvematrix` can be compiled from source on most platforms supported by both [AWS-LC](https://github.com/aws/aws-lc#platform-support) (on which this tool partially depends) and the [Rust compiler (with std support)](https://doc.rust-lang.org/rustc/platform-support.html).

This can be accomplished by one of the following methods:

- Cloning this repository, navigating to the `cli/` subdirectory, and running `cargo build --release`
- Running the following one-liner, without needing to clone the repository: `cargo install --git https://forgejo.ellis.link/continuwuation/resolvematrix resolvematrix-cli`

#### Example

```shell
$ resolvematrix continuwuity.org
Resolved continuwuity.org to base URL https://matrix.continuwuity.org:443 using step 3.2 (WellKnownHostPort)
Server is continuwuity version 26.9.1 (ddbdd1e)
Server has signing keys:
- ed25519:PwHlNsFu: 8eNx2s0zWW+heKAmOH5zKv/nCPkEpraDJfGHxDu6hFI
```

## Contributing

Resolvematrix is part of the [Continuwuity](https://continuwuity.org) project. Please see the
[Contributing guide](https://continuwuity.org/development/contributing) before submitting a pull request.

## Code of Conduct

Contributors are expected to follow the [Continuwuity Community Guidelines](https://continuwuity.org/community/guidelines).
