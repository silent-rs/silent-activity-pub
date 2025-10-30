use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub base_url: String,
}

impl AppConfig {
    pub fn load_from_env() -> Self {
        let base_url =
            env::var("AP_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        Self { base_url }
    }
}
