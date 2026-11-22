pub mod auth;

use axum::Router;
use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .nest("/api/auth", auth::auth_routes())
        .with_state(state)
}
