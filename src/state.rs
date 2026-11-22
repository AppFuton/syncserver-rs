use axum::extract::FromRef;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use crate::config::Config;
use crate::db::Repository;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub repo: Arc<dyn Repository>,
    pub last_timestamp: Arc<AtomicI64>,
}

impl AppState {
    pub fn new(config: Arc<Config>, repo: Arc<dyn Repository>) -> Self {
        Self {
            config,
            repo,
            last_timestamp: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn next_timestamp(&self) -> i64 {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut current = self.last_timestamp.load(Ordering::Acquire);
        loop {
            let next = std::cmp::max(now_ms, current + 1);
            match self.last_timestamp.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
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
