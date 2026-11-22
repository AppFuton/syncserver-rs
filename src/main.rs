use std::sync::Arc;
use syncserver_rs::config::Config;
use syncserver_rs::error::AppError;
use syncserver_rs::routes::create_router;
use syncserver_rs::AppState;

fn mask_database_url(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        if let Some((_userinfo, host_and_path)) = rest.split_once('@') {
            format!("{scheme}://****@{host_and_path}")
        } else {
            url.to_string()
        }
    } else {
        url.to_string()
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "syncserver_rs=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let bind_addr = format!("{}:{}", config.host, config.port);
    tracing::info!(
        "Starting syncserver-rs v{} on {} with db {}",
        env!("CARGO_PKG_VERSION"),
        bind_addr,
        mask_database_url(&config.database_url)
    );

    let repo = syncserver_rs::db::init_repository(&config.database_url).await?;

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Listening on http://{}", bind_addr);

    let state = AppState::new(Arc::new(config), repo);
    let app = create_router(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Server shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::warn!("Failed to install SIGTERM signal handler: {err}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        },
    }
}
