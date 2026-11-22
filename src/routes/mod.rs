pub mod auth;
pub mod items;
pub mod vault;

use axum::Router;
use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .nest("/api/auth", auth::auth_routes())
        .nest("/api/vault", vault::vault_routes())
        .nest("/api/items", items::items_routes())
        .with_state(state)
}
