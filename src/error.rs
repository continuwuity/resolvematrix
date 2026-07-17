use thiserror::Error;

/// Error type for Matrix server resolution.
#[derive(Debug, Error)]
pub enum ServerResolutionError {
    #[error("DNS resolution error: {0}")]
    Dns(#[from] hickory_resolver::net::NetError),
}

/// Error type for Matrix server resolution.
#[derive(Debug, Error)]
pub enum ServerResolverBuilderError {
    #[error("DNS resolver builder error: {0}")]
    Dns(#[from] hickory_resolver::net::NetError),

    #[error("Invalid builder options: {0}")]
    InvalidBuilderOptions(InvalidBuilderOption),

    #[error("HTTP client construction error: {0}")]
    HttpClientBuilder(reqwest::Error),
}

#[derive(Debug, Error)]
pub enum InvalidBuilderOption {
    #[error("`resolution_cache` and `cache_ttl` are mutually exclusive")]
    ResolutionCacheExclusive,
}
