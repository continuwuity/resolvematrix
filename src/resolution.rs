use hickory_resolver::TokioResolver;
use std::net::{IpAddr, SocketAddr};

/// Resolution steps as defined by the Matrix specification (v1.18)
///
/// https://spec.matrix.org/v1.18/server-server-api/#server-discovery
#[derive(Debug, Clone)]
pub enum ResolutionStep {
    /// Step 1
    ///
    /// > If the hostname is an IP literal, then that IP address should be used, together with the
    /// > given port number, or 8448 if no port is given. The target server must present a valid
    /// > certificate for the IP address. The `Host` header in the request should be set to the
    /// > server name, including the port if the server name included one.
    IPLiteral,

    /// Step 2
    ///
    /// > If the hostname is not an IP literal, and the server name includes an explicit port,
    /// > resolve the hostname to an IP address using CNAME, AAAA or A records. Requests are made
    /// > to the resolved IP address and given port with a `Host` header of the original server name
    /// > (with port). The target server must present a valid certificate for the hostname.
    HostPort,

    /// Step 3.1
    ///
    /// > If `<delegated_hostname>` is an IP literal, then that IP address should be used together
    /// > with the `<delegated_port>` or 8448 if no port is provided. The target server must present
    /// > a valid TLS certificate for the IP address. Requests must be made with a `Host` header
    /// > containing the IP address, including the port if one was provided.
    WellKnownIPLiteral,

    /// Step 3.2
    ///
    /// > If `<delegated_hostname>` is not an IP literal, and `<delegated_port>` is present, an
    /// > IP address is discovered by looking up CNAME, AAAA or A records for `<delegated_hostname>`.
    /// > The resulting IP address is used, alongside the `<delegated_port>`. Requests must be made
    /// > with a `Host` header of `<delegated_hostname>:<delegated_port>`. The target server must
    /// > present a valid certificate for `<delegated_hostname>`.
    WellKnownHostPort,

    /// Step 3.3
    ///
    /// > **\[Added in v1.8]** If `<delegated_hostname>` is not an IP literal and no `<delegated_port>`
    /// > is present, an SRV record is looked up for `_matrix-fed._tcp.<delegated_hostname>`. This may
    /// > result in another hostname (to be resolved using AAAA or A records) and port.
    /// > Requests should be made to the resolved IP address and port with a `Host` header containing
    /// > the `<delegated_hostname>`. The target server must present a valid certificate
    /// > for `<delegated_hostname>`.
    WellKnownSrvMatrixFed,

    /// Step 3.4
    ///
    /// > **\[Deprecated]** If `<delegated_hostname>` is not an IP literal, no `<delegated_port>` is
    /// > present, and a `_matrix-fed._tcp.<delegated_hostname>` SRV record was not found, an SRV
    /// > record is looked up for `_matrix._tcp.<delegated_hostname>`. This may result in another
    /// > hostname (to be resolved using AAAA or A records) and port. Requests should be made to the
    /// > resolved IP address and port with a `Host` header containing the `<delegated_hostname>`.
    /// > The target server must present a valid certificate for `<delegated_hostname>`.
    WellKnownSrvMatrix,

    /// Step 3.5
    ///
    /// > If no SRV record is found, an IP address is resolved using CNAME, AAAA or A records.
    /// > Requests are then made to the resolved IP address and a port of 8448, using a `Host`
    /// > header of `<delegated_hostname>`. The target server must present a valid certificate
    /// > for `<delegated_hostname>`.
    WellKnownDefaultPort,

    /// Step 4
    ///
    /// > **\[Added in v1.8]** If the `/.well-known` request resulted in an error response, a server
    /// > is found by resolving an SRV record for `_matrix-fed._tcp.<hostname>`. This may result in
    /// > a hostname (to be resolved using AAAA or A records) and port. Requests are made to the
    /// > resolved IP address and port, with a `Host` header of `<hostname>`. The target server must
    /// > present a valid certificate for `<hostname>`.
    SrvMatrixFed,

    /// Step 5
    ///
    /// > **\[Deprecated]** If the `/.well-known` request resulted in an error response, and a
    /// > `_matrix-fed._tcp.<hostname>` SRV record was not found, a server is found by resolving an
    /// > SRV record for `_matrix._tcp.<hostname>`. This may result in a hostname (to be resolved
    /// > using AAAA or A records) and port. Requests are made to the resolved IP address and port,
    /// > with a `Host` header of `<hostname>`. The target server must present a valid certificate
    /// > for `<hostname>`.
    SrvMatrix,

    /// Step 6
    ///
    /// > If the `/.well-known` request returned an error response, and no SRV records were found,
    /// > an IP address is resolved using CNAME, AAAA and A records. Requests are made to the
    /// > resolved IP address using port 8448 and a `Host` header containing the `<hostname>`. The
    /// > target server must present a valid certificate for `<hostname>`.
    DefaultPort,
}

impl ResolutionStep {
    #[allow(dead_code)]
    fn as_str(&self) -> &'static str {
        match self {
            ResolutionStep::IPLiteral => "1",
            ResolutionStep::HostPort => "2",
            ResolutionStep::WellKnownIPLiteral => "3.1",
            ResolutionStep::WellKnownHostPort => "3.2",
            ResolutionStep::WellKnownSrvMatrixFed => "3.3",
            ResolutionStep::WellKnownSrvMatrix => "3.4",
            ResolutionStep::WellKnownDefaultPort => "3.5",
            ResolutionStep::SrvMatrixFed => "4",
            ResolutionStep::SrvMatrix => "5",
            ResolutionStep::DefaultPort => "6",
        }
    }
}

/// Result of a Matrix server resolution.
///
/// Contains the resolved destination (IP/Port or Hostname/Port) and the
/// hostname to use for SNI/Host headers.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// The actual destination to connect to.
    pub destination: ResolvedDestination,

    /// The hostname to use for TLS SNI and HTTP Host header. May contain a port if the target
    /// has one (e.g. from looking up the resolution for `example.com:9090`).
    pub host: String,

    /// Whether the resolution requires using `host` as an SNI/Host override.
    pub is_override: bool,

    /// Which part of the spec was used to resolve the resolution.
    pub resolution_step: ResolutionStep,
}

impl Resolution {
    /// Get the base URL for making requests to this resolution.
    /// Uses the host field for proper SNI.
    #[must_use]
    pub fn base_url(&self) -> String {
        match &self.destination {
            ResolvedDestination::Literal(addr) => format!("https://{addr}"),
            ResolvedDestination::Named(_dest_host, dest_port) => {
                let port: u16 = dest_port.parse().unwrap_or(8448);
                if self.host.contains(':') {
                    format!("https://{}", self.host)
                } else {
                    format!("https://{}:{}", self.host, port)
                }
            }
        }
    }

    /// Get the hostname (without port) from the host field for DNS mapping.
    pub(crate) fn sni_hostname(&self) -> String {
        if let Some(host) = self.host.strip_prefix('[')
            && let Some(bracket_pos) = host.find(']')
        {
            return host[..bracket_pos].to_string();
        }

        if self.host.matches(':').count() == 1
            && let Some((hostname, _port)) = self.host.rsplit_once(':')
        {
            hostname.to_string()
        } else {
            self.host.clone()
        }
    }

    /// Get the destination address for DNS resolution mapping.
    pub(crate) async fn destination_addrs(
        &self,
        resolver: &TokioResolver,
    ) -> Option<Vec<SocketAddr>> {
        match &self.destination {
            ResolvedDestination::Literal(addr) => Some(vec![*addr]),
            ResolvedDestination::Named(dest_host, dest_port) => {
                let port: u16 = dest_port.parse().ok()?;

                // Try to parse as IP first
                if let Ok(ip) = dest_host.parse::<IpAddr>() {
                    return Some(vec![SocketAddr::new(ip, port)]);
                }

                // Resolve via DNS
                match resolver.lookup_ip(dest_host.as_str()).await {
                    Ok(lookup) => {
                        let addrs: Vec<SocketAddr> =
                            lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect();
                        if addrs.is_empty() { None } else { Some(addrs) }
                    }
                    Err(_) => None,
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn destination_addr(&self, resolver: &TokioResolver) -> Option<SocketAddr> {
        self.destination_addrs(resolver)
            .await
            .and_then(|addrs| addrs.into_iter().next())
    }
}

/// Represents the resolved destination for a Matrix server.
#[derive(Debug, Clone)]
pub enum ResolvedDestination {
    /// A literal IP address and port (e.g., 1.2.3.4:8448)
    Literal(SocketAddr),
    /// A named host and port (e.g., "matrix.org", "8448")
    Named(String, String),
}

impl ResolvedDestination {
    /// Get the destination hostname
    pub fn hostname(&self) -> String {
        match &self {
            ResolvedDestination::Literal(addr) => addr.ip().to_string(),
            ResolvedDestination::Named(dest_host, _dest_port) => dest_host.clone(),
        }
    }

    /// Get the destination port
    pub fn port(&self) -> u16 {
        match &self {
            ResolvedDestination::Literal(addr) => addr.port(),
            ResolvedDestination::Named(_dest_host, dest_port) => {
                dest_port.parse::<u16>().unwrap_or(8448)
            }
        }
    }

    /// Return the host:port formatted string of the resolved destination server (not SNI host)
    pub fn host_port(&self) -> String {
        match &self {
            ResolvedDestination::Literal(addr) => addr.to_string(),
            ResolvedDestination::Named(host, port) => format!("{host}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn socket_addrs_from_ips(ips: impl IntoIterator<Item = IpAddr>, port: u16) -> Vec<SocketAddr> {
        ips.into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    }

    #[rstest]
    #[tokio::test]
    async fn test_resolution() {
        let resolver = hickory_resolver::Resolver::builder_tokio()
            .unwrap()
            .build()
            .unwrap();
        let socketaddr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 8448);

        let literal_ip = Resolution {
            destination: ResolvedDestination::Literal(socketaddr),
            host: "127.0.0.1".to_string(),
            is_override: false,
            resolution_step: ResolutionStep::IPLiteral,
        };
        assert_eq!(
            literal_ip.destination_addrs(&resolver).await,
            Some(vec![socketaddr])
        );
        assert_eq!(
            literal_ip.destination_addr(&resolver).await,
            Some(socketaddr)
        );
        assert_eq!(literal_ip.base_url(), "https://127.0.0.1:8448");
        assert_eq!(literal_ip.sni_hostname(), "127.0.0.1");

        let named_ip = Resolution {
            destination: ResolvedDestination::Named(
                socketaddr.ip().to_string(),
                socketaddr.port().to_string(),
            ),
            host: "127.0.0.1".to_string(),
            is_override: false,
            resolution_step: ResolutionStep::IPLiteral,
        };
        assert_eq!(
            named_ip.destination_addrs(&resolver).await,
            Some(vec![socketaddr])
        );
        assert_eq!(named_ip.destination_addr(&resolver).await, Some(socketaddr));
        assert_eq!(named_ip.base_url(), "https://127.0.0.1:8448");
        assert_eq!(named_ip.sni_hostname(), "127.0.0.1");

        let named_with_port_in_host = Resolution {
            destination: ResolvedDestination::Named("example.com".to_string(), "9090".to_string()),
            host: "example.com:9090".to_string(),
            is_override: true,
            resolution_step: ResolutionStep::HostPort,
        };
        assert_eq!(
            named_with_port_in_host.base_url(),
            "https://example.com:9090"
        );
        assert_eq!(named_with_port_in_host.sni_hostname(), "example.com");

        let ipv6_host = Resolution {
            destination: ResolvedDestination::Literal(socketaddr),
            host: "[::1]:8448".to_string(),
            is_override: false,
            resolution_step: ResolutionStep::IPLiteral,
        };
        assert_eq!(ipv6_host.sni_hostname(), "::1");

        let bare_ipv6_host = Resolution {
            destination: ResolvedDestination::Literal(socketaddr),
            host: "::1".to_string(),
            is_override: false,
            resolution_step: ResolutionStep::IPLiteral,
        };
        assert_eq!(bare_ipv6_host.sni_hostname(), "::1");

        let invalid_dns_address = Resolution {
            destination: ResolvedDestination::Named(
                "testdomain.invalid".to_string(),
                "9090".to_string(),
            ),
            host: "testdomain.invalid:9090".to_string(),
            is_override: true,
            resolution_step: ResolutionStep::HostPort,
        };
        assert_eq!(invalid_dns_address.destination_addr(&resolver).await, None);
    }

    #[test]
    fn test_socket_addrs_from_ips_preserves_order() {
        let addrs = socket_addrs_from_ips(
            [
                IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
                IpAddr::from([127, 0, 0, 1]),
            ],
            8448,
        );

        assert_eq!(
            addrs,
            vec![
                SocketAddr::new(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), 8448),
                SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 8448),
            ]
        );
    }

    #[rstest]
    fn test_resolved_destination() {
        let literal =
            ResolvedDestination::Literal(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 8448));
        assert_eq!(literal.hostname(), "127.0.0.1");
        assert_eq!(literal.port(), 8448);
        assert_eq!(literal.host_port(), "127.0.0.1:8448");

        let named = ResolvedDestination::Named("example.com".to_string(), "8448".to_string());
        assert_eq!(named.hostname(), "example.com");
        assert_eq!(named.port(), 8448);
        assert_eq!(named.host_port(), "example.com:8448");
    }
}
