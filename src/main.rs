use std::sync::Arc;
use syncserver_rs::config::Config;
use syncserver_rs::db::init_repository;
use syncserver_rs::error::AppError;
use syncserver_rs::routes::create_router;
use syncserver_rs::AppState;

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

    let repo = init_repository(&config.database_url).await?;
    let state = AppState::new(Arc::new(config), repo);
    let _app = create_router(state);

    Ok(())
}

