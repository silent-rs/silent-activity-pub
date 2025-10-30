use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub base_url: String,
    #[allow(dead_code)]
    pub sign_enable: bool,
    #[allow(dead_code)]
    pub sign_key_id: String,
    #[allow(dead_code)]
    pub sign_shared_secret: String,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
    pub backoff_max_retries: usize,
}

impl AppConfig {
    pub fn load_from_env() -> Self {
        let base_url =
            env::var("AP_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let sign_enable = env::var("AP_SIGN_ENABLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let sign_key_id = env::var("AP_SIGN_KEY_ID").unwrap_or_else(|_| "local#main".to_string());
        let sign_shared_secret = env::var("AP_SIGN_SECRET").unwrap_or_default();
        let backoff_base_ms = env::var("AP_BACKOFF_BASE_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(500);
        let backoff_max_ms = env::var("AP_BACKOFF_MAX_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        let backoff_max_retries = env::var("AP_BACKOFF_MAX_RETRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        Self {
            base_url,
            sign_enable,
            sign_key_id,
            sign_shared_secret,
            backoff_base_ms,
            backoff_max_ms,
            backoff_max_retries,
        }
    }
}
