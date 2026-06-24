use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::cache::{Cache, CacheEntry, CacheLookup};
use crate::error::ResolveServerError;
use crate::resolution::{Resolution, ResolvedDestination};
use futures::StreamExt;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use num_traits::ToPrimitive;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json;

/// A custom DNS resolver for `reqwest` that handles Matrix server name resolution.
///
/// This resolver integrates with the `MatrixResolver` cache and logic to ensure that
/// HTTP requests made by `reqwest` are routed to the correct IP address and port
/// as discovered by the Matrix server discovery process.
///
/// It exists to ensure that the correct SNI is used. The resolver base URL is the
/// domain expected for SNI, and the `MatrixDnsResolver` resolves it to the correct destination.
#[derive(Clone)]
pub struct MatrixDnsResolver {
    resolver: Arc<TokioResolver>,
    cache: Cache,
    matrix_resolver: Arc<MatrixResolver>,
}

impl MatrixDnsResolver {
    pub(crate) fn new(
        resolver: Arc<TokioResolver>,
        cache: Cache,
        matrix_resolver: Arc<MatrixResolver>,
    ) -> Self {
        Self {
            resolver,
            cache,
            matrix_resolver,
        }
    }
}

impl reqwest::dns::Resolve for MatrixDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name_str = name.as_str().to_string();
        let resolver = self.resolver.clone();
        let cache = self.cache.clone();
        let matrix_resolver = self.matrix_resolver.clone();

        Box::pin(async move {
            // Check cache and determine what to do
            match cache.lookup(&name_str) {
                CacheLookup::Valid(resolution) => {
                    // Valid cached entry - use it
                    if let Some(addr) = resolution.destination_addr(&resolver).await {
                        tracing::trace!("DNS cache hit for {name_str} -> {addr}");
                        return Ok(Box::new(std::iter::once(addr))
                            as Box<dyn Iterator<Item = SocketAddr> + Send>);
                    }
                }
                CacheLookup::ExpiredOverride(server_name) => {
                    // Expired Matrix override - refetch via Matrix resolution
                    tracing::trace!("DNS cache expired override for {name_str}, refetching");
                    match matrix_resolver.resolve_server(&server_name).await {
                        Ok(resolution) => {
                            if let Some(addr) = resolution.destination_addr(&resolver).await {
                                return Ok(Box::new(std::iter::once(addr))
                                    as Box<dyn Iterator<Item = SocketAddr> + Send>);
                            } else {
                                // Something funky, they should re-resolve the server
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to refetch Matrix server {server_name}: {e:?}",);
                        }
                    }
                }
                CacheLookup::Miss => {
                    // No override - use standard DNS
                }
            }

            // Fallback: standard DNS lookup
            tracing::trace!("DNS fallback for {name_str}, using standard DNS");
            match resolver.lookup_ip(&name_str).await {
                Ok(lookup) => {
                    let addrs: Vec<SocketAddr> = lookup
                        .iter()
                        .map(|ip| SocketAddr::new(ip, 8448)) // Default Matrix port
                        .collect();
                    Ok(Box::new(addrs.into_iter()) as Box<dyn Iterator<Item = SocketAddr> + Send>)
                }
                Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            }
        })
    }
}

pub struct MatrixResolverBuilder {
    // Objects
    http_client: Option<Client>,
    dns_resolver: Option<Arc<TokioResolver>>,
    resolution_cache: Option<Cache>,

    // Options
    cache_ttl: Option<Duration>,
    dangerous_tls_accept_invalid_certs: bool,
}

impl Default for MatrixResolverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MatrixResolverBuilder {
    pub fn new() -> MatrixResolverBuilder {
        MatrixResolverBuilder {
            http_client: None,
            dns_resolver: None,
            resolution_cache: None,
            cache_ttl: None,
            dangerous_tls_accept_invalid_certs: false,
        }
    }

    pub fn http_client(mut self, client: Client) -> Self {
        self.http_client = Some(client);
        self
    }
    pub fn dns_resolver(mut self, resolver: Arc<TokioResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }
    pub fn resolution_cache(mut self, cache: Cache) -> Self {
        self.resolution_cache = Some(cache);
        self
    }
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }
    pub fn dangerous_tls_accept_invalid_certs(mut self, accept_invalid: bool) -> Self {
        self.dangerous_tls_accept_invalid_certs = accept_invalid;
        self
    }

    /// Create a new `MatrixResolver` with provided options or the default ones.
    ///
    /// # Errors
    ///
    /// Returns an error if the DNS resolver or HTTP client cannot be initialized.
    pub fn build(self) -> Result<MatrixResolver, ResolveServerError> {
        let client = self.http_client.unwrap_or(
            Client::builder()
                .tls_danger_accept_invalid_certs(self.dangerous_tls_accept_invalid_certs)
                .timeout(Duration::from_secs(10))
                .build()?,
        );

        let resolver = self.dns_resolver.unwrap_or(Arc::new(
            hickory_resolver::Resolver::builder_tokio()?.build()?,
        ));

        if self.resolution_cache.is_some() && self.cache_ttl.is_some() {
            return Err(ResolveServerError::InvalidBuilderOptions(
                "`resolution_cache` and `cache_ttl` are mutually exclusive".to_string(),
            ));
        }
        let cache = self.resolution_cache.unwrap_or(Cache::new(
            self.cache_ttl.unwrap_or(Duration::from_secs(300)),
        ));

        Ok(MatrixResolver {
            client,
            resolver,
            cache,
        })
    }
}

/// The main resolver struct for Matrix server resolution.
pub struct MatrixResolver {
    client: Client,
    resolver: Arc<TokioResolver>,
    cache: Cache,
}

impl MatrixResolver {
    /// Returns a builder object to be used to set additional options
    ///
    /// Example
    ///
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// # use resolvematrix::server::{MatrixResolver, MatrixResolverBuilder};
    /// let resolver = MatrixResolver::builder()
    ///     .cache_ttl(Duration::from_secs(10))
    ///     .build();
    ///
    /// // Or by directly accessing the builder
    /// let resolver = MatrixResolverBuilder::new()
    ///     .cache_ttl(Duration::from_secs(10))
    ///     .build();
    /// ```
    pub fn builder() -> MatrixResolverBuilder {
        MatrixResolverBuilder::new()
    }

    /// Create a new `MatrixResolver` with default options. For advanced options, use `MatrixResolverBuilder`
    /// or `MatrixResolver::builder()` (returns `MatrixResolverBuilder::new()`)
    ///
    /// # Errors
    ///
    /// Returns an error if the resolver fails to build. See also `MatrixResolverBuilder.build()`.
    pub fn new() -> Result<Self, ResolveServerError> {
        MatrixResolverBuilder::new().build()
    }

    /// Create a new `MatrixResolver` with a custom cache TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the DNS resolver or HTTP client cannot be initialized.
    #[deprecated(
        since = "0.0.5",
        note = "use `MatrixResolverBuilder::new().cache_ttl(Duration).build()` instead"
    )]
    pub fn new_with_ttl(cache_ttl: Duration) -> Result<Self, ResolveServerError> {
        MatrixResolverBuilder::new().cache_ttl(cache_ttl).build()
    }

    /// Create a client with custom builder that can be reused for all Matrix servers.
    ///
    /// The client uses a custom DNS resolver that dynamically looks up Matrix servers
    /// from the cache, allowing one client to handle all federation requests.
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn create_client_with_builder(
        self: &Arc<Self>,
        builder: reqwest::ClientBuilder,
    ) -> Result<Client, ResolveServerError> {
        let dns_resolver =
            MatrixDnsResolver::new(self.resolver.clone(), self.cache.clone(), self.clone());

        Ok(builder.dns_resolver(Arc::new(dns_resolver)).build()?)
    }

    /// Create a standard reqwest client that can be reused for all Matrix servers.
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn create_client(self: &Arc<Self>) -> Result<Client, ResolveServerError> {
        let builder = Client::builder().timeout(Duration::from_secs(10));
        self.create_client_with_builder(builder)
    }

    /// Resolve a Matrix server name and return the Resolution.
    ///
    /// The returned Resolution can be used to construct URLs via `resolution.base_url()`.
    /// When making a request, you must use a client built via the resolver to handle
    /// SRV records correctly.
    ///
    /// # Errors
    ///
    /// Returns an error if resolution fails (e.g. DNS failure, invalid response).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use resolvematrix::server::MatrixResolver;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let resolver = MatrixResolver::new()?;
    /// let resolution = resolver.resolve_server("matrix.org").await?;
    ///
    /// assert_eq!(resolution.host, "matrix-federation.matrix.org");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn resolve_server(
        &self,
        server_name: &str,
    ) -> Result<Resolution, ResolveServerError> {
        // Check cache first
        if let Some(resolution) = self.cache.get(server_name) {
            tracing::trace!("Cache hit for {server_name}");
            return Ok(resolution);
        }

        // Perform resolution
        let resolution = self.resolve_actual_dest(server_name).await?;

        // Cache the result
        self.cache.set(server_name.to_string(), &resolution);

        Ok(resolution)
    }

    /// Resolve the actual destination according to Matrix spec.
    /// <https://matrix.org/docs/spec/server_server/r0.1.4#resolving-server-names>
    #[tracing::instrument(
        name = "actual",
        level = "debug",
        skip(self),
        fields(dest = %dest)
    )]
    async fn resolve_actual_dest(&self, dest: &str) -> Result<Resolution, ResolveServerError> {
        // 1. If the hostname is an IP literal
        if let Some((ip, port)) = get_ip_with_port(dest) {
            tracing::info!(
                ip = %ip,
                port = port,
                step = "ip_literal",
                "Resolved IP literal with port"
            );
            let socket = SocketAddr::new(ip, port.unwrap_or(8448));
            return Ok(Resolution {
                destination: ResolvedDestination::Literal(socket),
                host: dest.to_owned(),
            });
        }

        // 2. Hostname with explicit port
        if let Some(pos) = dest.find(':') {
            let (host_part, port_part) = dest.split_at(pos);
            let port_str = port_part.trim_start_matches(':');
            tracing::info!(
                host = %host_part,
                port = %port_str,
                step = "explicit_port",
                "Resolved hostname with explicit port"
            );
            return Ok(Resolution {
                destination: ResolvedDestination::Named(host_part.to_owned(), port_str.to_owned()),
                host: dest.to_owned(),
            });
        }

        // 3. Well-known delegation
        if let Some(res) = self.resolve_well_known(dest).await {
            tracing::info!(?res, step = "well_known", "Resolved .well-known delegation");
            return match res {
                // 3.1: delegated_hostname is an IP literal, optionally with port else default
                WellKnownServerResult::Ip(ip, port) => {
                    tracing::info!(
                        ip = %ip,
                        port = port.unwrap_or(8448),
                        step = "well_known_ip_literal",
                        "Resolved .well-known IP literal"
                    );
                    let socket = SocketAddr::new(ip, port.unwrap_or(8448));
                    Ok(Resolution {
                        destination: ResolvedDestination::Literal(socket),
                        host: dest.to_owned(),
                    })
                }
                // 3.2: Hostname with explicit port in .well-known
                WellKnownServerResult::Domain(domain, Some(port)) => {
                    tracing::info!(
                        domain = %domain,
                        port = port,
                        step = "well_known_domain",
                        "Resolved .well-known domain with port"
                    );
                    Ok(Resolution {
                        destination: ResolvedDestination::Named(domain.clone(), port.to_string()),
                        host: format!("{domain}:{port}"),
                    })
                }
                WellKnownServerResult::Domain(domain, None) => {
                    // 3.3/3.4: Hostname, no port in .well-known
                    if let Some((srv_host, srv_port)) = self.query_srv_record(&domain).await? {
                        tracing::info!(
                            srv_host = %srv_host,
                            srv_port = srv_port,
                            step = "well_known_host_srv",
                            "Resolved SRV from .well-known hostname without port"
                        );
                        Ok(Resolution {
                            destination: ResolvedDestination::Named(srv_host, srv_port.to_string()),
                            host: domain,
                        })
                    } else {
                        // 3.5: No SRV, fallback to A/AAAA/CNAME + 8448
                        tracing::trace!(
                            delegated = %domain,
                            step = "well_known_fallback",
                            "Fallback to .well-known host with default port"
                        );
                        Ok(Resolution {
                            destination: ResolvedDestination::Named(
                                domain.clone(),
                                "8448".to_owned(),
                            ),
                            host: domain,
                        })
                    }
                }
            };
        }

        // 4. SRV lookup on original hostname
        if let Some((srv_host, srv_port)) = self.query_srv_record(dest).await? {
            tracing::trace!(
                srv_host = %srv_host,
                srv_port = srv_port,
                step = "srv_lookup",
                "Resolved SRV record on original hostname"
            );
            return Ok(Resolution {
                destination: ResolvedDestination::Named(srv_host, srv_port.to_string()),
                host: dest.to_owned(),
            });
        }

        // 5. Fallback: A/AAAA/CNAME + 8448
        tracing::trace!(
            host = %dest,
            step = "fallback",
            "Fallback to original hostname with default port"
        );
        Ok(Resolution {
            destination: ResolvedDestination::Named(dest.to_owned(), "8448".to_owned()),
            host: dest.to_owned(),
        })
    }

    /// Resolve .well-known delegation for a hostname.
    #[tracing::instrument(
        level = "trace",
        skip(self),
        fields(hostname = %hostname)
    )]
    async fn resolve_well_known(&self, hostname: &str) -> Option<WellKnownServerResult> {
        #[derive(Deserialize)]
        struct WellKnown {
            #[serde(rename = "m.server")]
            m_server: String,
        }

        let url = format!("https://{hostname}/.well-known/matrix/server");
        tracing::trace!(?url, "Fetching .well-known matrix server");
        let Ok(resp) = self.client.get(&url).send().await else {
            tracing::trace!(?url, "Failed to fetch well-known matrix server");
            return None;
        };
        if resp.status() != StatusCode::OK {
            tracing::trace!(
                ?url,
                status = resp.status().as_u16(),
                "Response status not 200 when fetching .well-known"
            );
            return None;
        }

        let json_data = match resp.limit_read().await {
            Ok(s) => serde_json::from_slice(&s),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    ?url,
                    limit = MAX_WELL_KNOWN_SIZE,
                    "Well-known response size exceeds maximum"
                );
                return None;
            }
        };
        let wk: WellKnown = match json_data {
            Ok(wk) => wk,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    url = %url,
                    "Failed to parse .well-known matrix server JSON"
                );
                return None;
            }
        };

        if let Some((ip, port)) = get_ip_with_port(&wk.m_server) {
            tracing::trace!(
                ip = %ip,
                port = ?port,
                "Parsed .well-known matrix server IP and port"
            );
            return Some(WellKnownServerResult::Ip(ip, port));
        }
        let (host, port) = Self::parse_server_name(&wk.m_server);
        tracing::trace!(
            well_known_host = %host,
            well_known_port = ?port,
            "Parsed .well-known matrix server domain"
        );
        Some(WellKnownServerResult::Domain(host, port))
    }

    /// Parses a Matrix server name into `(hostname, Option<port>)`
    #[tracing::instrument(
        name = "parse_server_name",
        level = "trace",
        fields(server_name = %server_name)
    )]
    pub(crate) fn parse_server_name(server_name: &str) -> (String, Option<u16>) {
        if let Some((host, port)) = server_name.rsplit_once(':')
            && let Ok(port) = u16::from_str(port)
        {
            return (host.to_string(), Some(port));
        }
        (server_name.to_string(), None)
    }

    /// Query SRV records for a hostname, returning (target, port) if found.
    #[tracing::instrument(
        level = "trace",
        skip(self),
        fields(hostname = %hostname)
    )]
    async fn query_srv_record(
        &self,
        hostname: &str,
    ) -> Result<Option<(String, u16)>, ResolveServerError> {
        let srv_names = [
            format!("_matrix-fed._tcp.{hostname}"),
            format!("_matrix._tcp.{hostname}"),
        ];
        for srv in &srv_names {
            tracing::trace!(srv = %srv, "Querying SRV record");
            let lookup = self.resolver.srv_lookup(srv).await;
            if let Ok(result) = lookup
                && let Some(record) = result
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::SRV(srv) => Some(srv),
                        _ => None,
                    })
                    .next()
            {
                let target = record.target.to_utf8();
                let port = record.port;
                return Ok(Some((target.trim_end_matches('.').to_owned(), port)));
            }
        }
        tracing::trace!(hostname = %hostname, "No SRV records found for hostname");
        Ok(None)
    }

    /// Remove a single entry from the cache, returning the removed entry if it existed
    #[tracing::instrument(
        level = "trace",
        skip(self),
        fields(hostname = %hostname)
    )]
    pub fn remove_cache_entry(&self, hostname: &str) -> Option<CacheEntry> {
        self.cache.remove_entry(hostname)
    }

    /// Clear entire cache
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn clear_cache(&self) {
        self.cache.clear()
    }
}

pub const MAX_WELL_KNOWN_SIZE: u64 = 262_144; // 256 KiB

#[allow(async_fn_in_trait)]
pub trait LimitReadExt {
    /// Reads the response body while enforcing a maximum size limit to prevent
    /// memory exhaustion.
    async fn limit_read(self) -> Result<Vec<u8>, ResolveServerError>;
}

impl LimitReadExt for reqwest::Response {
    async fn limit_read(self) -> Result<Vec<u8>, ResolveServerError> {
        if self
            .content_length()
            .is_some_and(|len| len > MAX_WELL_KNOWN_SIZE)
        {
            return Err(ResolveServerError::WellKnownTooLarge);
        }
        let mut data = Vec::new();
        let mut reader = self.bytes_stream();

        while let Some(chunk) = reader.next().await {
            let chunk = chunk?;
            data.extend_from_slice(&chunk);

            if data.len()
                > MAX_WELL_KNOWN_SIZE
                    .to_usize()
                    .expect("max_size must fit in usize")
            {
                return Err(ResolveServerError::WellKnownTooLarge);
            }
        }

        Ok(data)
    }
}

#[derive(Debug)]
enum WellKnownServerResult {
    Ip(IpAddr, Option<u16>),
    Domain(String, Option<u16>),
}

/// If the string is an IP literal (with optional port), returns (`IpAddr`, port).
#[tracing::instrument(
    name = "get_ip_with_port",
    level = "trace",
    fields(input = %s)
)]
fn get_ip_with_port(s: &str) -> Option<(IpAddr, Option<u16>)> {
    // Try SocketAddr first (IP:port)
    if let Ok(sock) = SocketAddr::from_str(s) {
        tracing::trace!(
            ip = %sock.ip(),
            port = sock.port(),
            "Parsed SocketAddr from input"
        );
        return Some((sock.ip(), Some(sock.port())));
    }
    // Try IP only
    if let Ok(ip) = IpAddr::from_str(s) {
        tracing::trace!(
            ip = %ip,
            port = 8448,
            "Parsed IpAddr from input, using default port"
        );
        return Some((ip, None));
    }
    tracing::debug!(input = %s, "Input is not an IP literal");
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use assertables::{assert_none, assert_some};
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use rstest::rstest;
    use tracing::debug;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    /// Helper function to initialize tracing for tests
    pub(crate) fn init_tracing() {
        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_test_writer()
                    .with_target(false),
            )
            .try_init();
    }

    /// Test IP literal detection with parameterized cases
    #[rstest]
    #[case::ipv4_port("127.0.0.1:8080", Some((IpAddr::from([127, 0, 0, 1]), Some(8080))))]
    #[case::ipv4_no_port("127.0.0.1", Some((IpAddr::from([127, 0, 0, 1]), None)))]
    #[case::ipv4_invalid_port("127.0.0.1:invalid", None)]
    #[case::ipv4_multiple_port("127.0.0.1:8080:invalid", None)]
    #[case::ipv6_port("[::1]:8080", Some((IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), Some(8080))))]
    #[case::ipv6_no_port("::1", Some((IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), None)))]
    #[case::ipv6_invalid_port("[::1]:invalid", None)]
    #[case::ipv6_multiple_ports("[::1]:8080:invalid", None)]
    #[case::ipv6_invalid_addr("::1:8080:invalid", None)]
    #[case::hostname("example.com", None)]
    #[case::hostname_with_port("example.com:8448", None)]
    #[case::invalid("not-an-ip", None)]
    fn test_get_ip_with_port(#[case] input: &str, #[case] expected: Option<(IpAddr, Option<u16>)>) {
        assert_eq!(get_ip_with_port(input), expected);
    }

    #[allow(dead_code)] // Used as part of JSON later on, where entire JSON structure is printed to console for test
    #[derive(Deserialize, Debug)]
    struct ServerVersionEndpoint {
        pub server: ServerVersionServer,
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct ServerVersionServer {
        pub name: String,
        pub version: String,
    }

    /// Parameterized test for server resolution.
    #[rstest]
    #[tokio::test]
    #[case::maunium_net("maunium.net")]
    #[case::timedout_uk_port("timedout.uk:69")]
    #[case::nexy7574_co_uk("nexy7574.co.uk")]
    #[case::matrix_org("matrix.org")]
    #[case::matrixrooms_info("matrixrooms.info")]
    #[case::resolvematrix_2_port("2.s.resolvematrix.dev:7652")]
    #[case::resolvematrix_3b("3b.s.resolvematrix.dev")]
    #[case::resolvematrix_3c("3c.s.resolvematrix.dev")]
    #[case::resolvematrix_3d("3d.s.resolvematrix.dev")]
    #[case::resolvematrix_4("4.s.resolvematrix.dev")]
    #[case::resolvematrix_5("5.s.resolvematrix.dev")]
    #[case::resolvematrix_3c_msc4040("3c.msc4040.s.resolvematrix.dev")]
    #[case::resolvematrix_4_msc4040("4.msc4040.s.resolvematrix.dev")]
    async fn test_server_resolver(#[case] server_name: &str) {
        init_tracing();

        let resolver = Arc::new(MatrixResolver::new().unwrap());

        tracing::info!("Testing {server_name}");

        // Resolve server
        let resolution = dbg!(resolver.resolve_server(server_name).await.unwrap());

        // Create client with custom DNS resolver
        let builder = Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = resolver.create_client_with_builder(builder).unwrap();

        // Build URL using the resolution's base_url
        let url = format!("{}/_matrix/federation/v1/version", resolution.base_url());

        debug!(?resolution, ?url, "Resolved server");

        let request = client.get(&url).build().unwrap();

        let response = client.execute(request).await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                let json: Option<ServerVersionEndpoint> = resp.json().await.ok();
                debug!(%status, "Response");

                if status == StatusCode::OK {
                    tracing::info!(
                        "✓ Successfully fetched federation version from {server_name}: {json:?}"
                    );
                } else {
                    tracing::warn!("Server {server_name} returned non-200 status: {status}.");
                    panic!();
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch federation version from {server_name}: {e:?}");
                panic!();
            }
        }
    }

    /// Test `parse_server_name` function with various inputs
    #[rstest]
    #[case::no_port("matrix.org", "matrix.org", None)]
    #[case::with_port("matrix.org:8448", "matrix.org", Some(8448))]
    #[case::high_port("server.com:9999", "server.com", Some(9999))]
    #[case::low_port("localhost:80", "localhost", Some(80))]
    #[case::ipv4_with_port("192.168.1.1:8008", "192.168.1.1", Some(8008))]
    fn test_parse_server_name(
        #[case] input: &str,
        #[case] expected_host: &str,
        #[case] expected_port: Option<u16>,
    ) {
        init_tracing();

        let (host, port) = MatrixResolver::parse_server_name(input);
        assert_eq!(host, expected_host);
        assert_eq!(port, expected_port);
    }

    /// Test resolution of well-known servers
    #[rstest]
    #[tokio::test]
    #[case::maunium("maunium.net")]
    #[case::nexy("nexy7574.co.uk")]
    async fn test_well_known_resolution(#[case] server_name: &str) {
        init_tracing();

        let resolver = MatrixResolver::new().unwrap();
        let resolution = resolver.resolve_server(server_name).await;

        assert!(
            resolution.is_ok(),
            "Failed to resolve {server_name}: {:?}",
            resolution.err()
        );

        let resolved = resolution.unwrap();
        tracing::info!(
            "Resolved {server_name} to destination: {:?}, host: {}",
            resolved.destination,
            resolved.host
        );

        // Verify the resolution contains valid data
        match &resolved.destination {
            ResolvedDestination::Literal(addr) => {
                assert!(addr.port() > 0, "Port should be greater than 0");
            }
            ResolvedDestination::Named(host, port) => {
                assert!(!host.is_empty(), "Host should not be empty");
                assert!(!port.is_empty(), "Port should not be empty");
                let port_num: u16 = port.parse().expect("Port should be a valid number");
                assert!(port_num > 0, "Port should be greater than 0");
            }
        }
    }

    /// Test servers with explicit ports
    #[rstest]
    #[case::standard_port("matrix.org:8448")]
    #[case::custom_port("timedout.uk:69")]
    #[case::high_port("test.server:9999")]
    #[tokio::test]
    async fn test_explicit_port_resolution(#[case] server_name: &str) {
        init_tracing();

        let resolver = MatrixResolver::new().unwrap();
        let resolution = resolver.resolve_server(server_name).await;

        assert!(
            resolution.is_ok(),
            "Failed to resolve {server_name}: {:?}",
            resolution.err()
        );

        let resolved = resolution.unwrap();

        // When a port is explicitly specified, it should be preserved
        match &resolved.destination {
            ResolvedDestination::Named(_, port) => {
                let expected_port = server_name.split(':').nth(1).unwrap();
                assert_eq!(
                    port, expected_port,
                    "Port should match the explicit port in server name"
                );
            }
            ResolvedDestination::Literal(addr) => {
                let expected_port: u16 = server_name.split(':').nth(1).unwrap().parse().unwrap();
                assert_eq!(
                    addr.port(),
                    expected_port,
                    "Port should match the explicit port in server name"
                );
            }
        }
    }

    /// Test IP literal resolution
    #[rstest]
    #[case::ipv4_default("192.168.1.1")]
    #[case::ipv4_custom_port("192.168.1.1:8008")]
    #[case::ipv6_default("::1")]
    #[case::ipv6_custom_port("[::1]:8008")]
    #[tokio::test]
    async fn test_ip_literal_resolution(#[case] server_name: &str) {
        init_tracing();

        let resolver = MatrixResolver::new().unwrap();
        let resolution = resolver.resolve_server(server_name).await;

        assert!(
            resolution.is_ok(),
            "Failed to resolve {server_name}: {:?}",
            resolution.err()
        );

        let resolved = resolution.unwrap();

        // IP literals should always resolve to Literal variant
        match &resolved.destination {
            ResolvedDestination::Literal(addr) => {
                assert!(addr.port() > 0, "Port should be greater than 0");
                // If no port specified, should default to 8448
                if !server_name.contains(':') {
                    assert_eq!(addr.port(), 8448, "Should default to port 8448");
                }
            }
            ResolvedDestination::Named(..) => {
                panic!("IP literal should resolve to Literal variant")
            }
        }
    }

    /// Run tests against the resolvematrix.dev servers
    #[rstest]
    #[case::resolvematrix_2( // Explicit port
        "2.s.resolvematrix.dev:7652",
        "2.s.resolvematrix.dev",
        7652,
        "2.s.resolvematrix.dev:7652"
    )]
    #[case::resolvematrix_3b( // Delegated explicit port
        "3b.s.resolvematrix.dev",
        "wk.3b.s.resolvematrix.dev",
        7753,
        "wk.3b.s.resolvematrix.dev:7753"
    )]
    #[case::resolvematrix_3c( // Delegated `matrix` SRV
        "3c.s.resolvematrix.dev",
        "srv.wk.3c.s.resolvematrix.dev",
        7754,
        "wk.3c.s.resolvematrix.dev"
    )]
    #[case::resolvematrix_3d( // Delegated default port
        "3d.s.resolvematrix.dev",
        "wk.3d.s.resolvematrix.dev",
        8448,
        "wk.3d.s.resolvematrix.dev"
    )]
    #[case::resolvematrix_4( // `matrix` SRV
        "4.s.resolvematrix.dev",
        "srv.4.s.resolvematrix.dev",
        7855,
        "4.s.resolvematrix.dev"
    )]
    #[case::resolvematrix_5( // Default port
        "5.s.resolvematrix.dev",
        "5.s.resolvematrix.dev",
        8448,
        "5.s.resolvematrix.dev"
    )]
    #[case::resolvematrix_3c_msc4040( // Delegated `matrix-fed` SRV
        "3c.msc4040.s.resolvematrix.dev",
        "srv.wk.3c.msc4040.s.resolvematrix.dev",
        7053,
        "wk.3c.msc4040.s.resolvematrix.dev"
    )]
    #[case::resolvematrix_4_msc4040(  // `matrix-fed` SRV
        "4.msc4040.s.resolvematrix.dev",
        "srv.4.msc4040.s.resolvematrix.dev",
        7054,
        "4.msc4040.s.resolvematrix.dev"
    )]
    #[tokio::test]
    async fn test_resolvematrix_suite(
        #[case] input: &str,
        #[case] expected_hostname: &str,
        #[case] expected_port: u16,
        #[case] expected_sni: &str,
    ) {
        init_tracing();

        let resolver = Arc::new(MatrixResolver::new().unwrap());

        tracing::info!("Testing {input}");

        // Resolve server
        let resolution = resolver.resolve_server(input).await.unwrap();

        assert_eq!(resolution.destination.hostname(), expected_hostname);
        assert_eq!(resolution.destination.port(), expected_port);
        assert_eq!(resolution.host, expected_sni);
    }

    /// Demonstrate reuse of the same client across different resolutions
    #[tokio::test]
    async fn test_client_reuse() {
        init_tracing();

        let resolver = Arc::new(MatrixResolver::new().unwrap());

        // Create ONE client that will be reused for all servers
        let builder = Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = resolver.create_client_with_builder(builder).unwrap();

        let servers = vec!["matrix.org", "nexy7574.co.uk", "matrixrooms.info"];

        for server_name in servers {
            tracing::info!("Testing {server_name} with reused client");

            // Resolve the server
            let resolution = resolver.resolve_server(server_name).await.unwrap();

            // Make a request
            let url = format!("{}/_matrix/federation/v1/version", resolution.base_url());

            debug!(?resolution, ?url, "Resolved server");

            let response = client.get(&url).send().await;

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    tracing::info!("✓ {server_name} returned status {status}");
                    assert_eq!(status, StatusCode::OK);
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch from {server_name}: {e:?}");
                    panic!("Request failed");
                }
            }
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_builder() {
        init_tracing();

        let client = Client::builder().build().unwrap();
        let dns_resolver = Arc::new(
            hickory_resolver::Resolver::builder_tokio()
                .unwrap()
                .build()
                .unwrap(),
        );
        let cache = Cache::new(Duration::from_secs(10));

        let resolver = MatrixResolverBuilder::new()
            .http_client(client)
            .dns_resolver(dns_resolver)
            .resolution_cache(cache)
            .build();

        assert!(resolver.is_ok());

        let ttl_resolver = MatrixResolverBuilder::new()
            .cache_ttl(Duration::from_secs(69))
            .build()
            .unwrap();
        assert_eq!(ttl_resolver.cache.ttl, Duration::from_secs(69));

        let cache2 = Cache::new(Duration::from_secs(10));
        assert!(
            MatrixResolverBuilder::new()
                .resolution_cache(cache2)
                .cache_ttl(Duration::from_secs(69))
                .build()
                .is_err()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_invalid_well_known() {
        init_tracing();

        let correct_json_server = MockServer::start();
        let _correct_json_mock = correct_json_server.mock(|when, then| {
            when.method(GET).path("/.well-known/matrix/server");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"m.server":"localhost:9090"}"#);
        });
        let correct_json_server_port = correct_json_server.port();
        let correct_json_server_address = format!("localhost.localhost:{correct_json_server_port}");

        let broken_json_server = MockServer::start();
        let _broken_json_mock = broken_json_server.mock(|when, then| {
            when.method(GET).path("/.well-known/matrix/server");
            then.status(200)
                .header("content-type", "application/json")
                .body("{");
        });
        let broken_json_server_port = broken_json_server.port();
        let broken_json_server_address = format!("localhost.localhost:{broken_json_server_port}");

        let oversize_response_server = MockServer::start();
        let _oversize_response_mock = oversize_response_server.mock(|when, then| {
            when.method(GET).path("/.well-known/matrix/server");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    (0..(MAX_WELL_KNOWN_SIZE * 2))
                        .map(|_| "X")
                        .collect::<String>(),
                );
        });
        let oversize_response_server_port = oversize_response_server.port();
        let oversize_response_server_address =
            format!("localhost.localhost:{oversize_response_server_port}");

        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("failed to initialize aws_lc_rs crypto provider");

        let resolver = Arc::new(
            MatrixResolverBuilder::new()
                .dangerous_tls_accept_invalid_certs(true)
                .build()
                .unwrap(),
        );

        let resolved_correct_json = dbg!(
            resolver
                .resolve_well_known(correct_json_server_address.as_str())
                .await
        );
        let resolved_broken_json = dbg!(
            resolver
                .resolve_well_known(broken_json_server_address.as_str())
                .await
        );
        let resolved_oversize_response = dbg!(
            resolver
                .resolve_well_known(oversize_response_server_address.as_str())
                .await
        );

        assert_some!(resolved_correct_json);
        assert_none!(resolved_broken_json);
        assert_none!(resolved_oversize_response);
    }
}
