use syncserver_rs::config::Config;
use syncserver_rs::error::AppError;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::from_env()?;
    tracing::info!(
        "Starting syncserver-rs on {}:{} with db {}",
        config.host,
        config.port,
        config.database_url
    );

    Ok(())
}
