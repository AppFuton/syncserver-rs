use axum::extract::FromRef;
use std::sync::Arc;

use crate::config::Config;
use crate::db::Repository;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub repo: Arc<dyn Repository>,
}

impl AppState {
    pub fn new(config: Arc<Config>, repo: Arc<dyn Repository>) -> Self {
        Self { config, repo }
    }
}

impl FromRef<AppState> for Arc<Config> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.config)
    }
}

impl FromRef<AppState> for Arc<dyn Repository> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.repo)
    }
}
