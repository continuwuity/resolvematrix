use thiserror::Error;

/// Error type for Matrix server resolution.
#[derive(Debug, Error)]
pub enum ResolveServerError {
    #[error("Failed to parse address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("DNS resolution error: {0}")]
    Dns(#[from] hickory_resolver::net::NetError),

    #[error("Invalid port number: {0}")]
    InvalidPort(#[from] std::num::ParseIntError),

    #[error("Invalid builder options: {0}")]
    InvalidBuilderOptions(String),

    #[error("Invalid UTF-8 data")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("Response .well-known too large")]
    WellKnownTooLarge,

    #[error("Unexpected error: {0}")]
    Other(String),
}
