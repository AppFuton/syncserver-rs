pub mod auth;
pub mod vault;

use axum::Router;
use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .nest("/api/auth", auth::auth_routes())
        .nest("/api/vault", vault::vault_routes())
        .with_state(state)
}
