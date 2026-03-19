use resolvematrix::server::MatrixResolver;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolver = Arc::new(MatrixResolver::new()?);

    let server_name = "matrix.org";
    let resolution = resolver.resolve_server(server_name).await?;

    // To make a federation request, we need to use a HTTP
    // client that has been built by the resolver.
    let client = resolver.create_client().unwrap();

    // First, we construct the target URL using the base URL
    let url = format!("{}/_matrix/federation/v1/version", resolution.base_url());
    // Then, we send the request using the HTTP client.
    let response = client.get(&url).send().await?;

    println!("{}", response.text().await?);

    Ok(())
}
