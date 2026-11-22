pub mod auth;
pub mod health;
pub mod items;
pub mod vault;

use axum::{routing::get, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health::health_check))
        .route("/health", get(health::health_check))
        .nest("/api/auth", auth::auth_routes())
        .nest("/api/vault", vault::vault_routes())
        .nest("/api/items", items::items_routes())
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any)
                .expose_headers([
                    axum::http::header::ETAG,
                    axum::http::header::IF_MATCH,
                    axum::http::header::IF_NONE_MATCH,
                ]),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

