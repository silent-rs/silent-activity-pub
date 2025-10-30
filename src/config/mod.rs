use std::env;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub base_url: String,
    // 监听地址
    pub listen_addr: String,
    #[allow(dead_code)]
    pub sign_enable: bool,
    #[allow(dead_code)]
    pub sign_key_id: String,
    #[allow(dead_code)]
    pub sign_shared_secret: String,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
    pub backoff_max_retries: usize,
    // 去重后端：memory | sled
    pub dedup_backend: String,
    // sled 路径
    pub sled_path: String,
    // 入站验签：允许的时间偏移（秒）
    pub sign_max_skew_sec: u64,
    // 出站签名算法：hmac|rsa|ed25519
    pub sign_alg: String,
    // 出站私钥路径（当 alg=rsa/ed25519 时必需）
    pub sign_priv_key_path: String,
    // 出站请求超时（毫秒）
    pub http_timeout_ms: u64,
    // 是否启用真实 HTTP/HTTPS 投递
    pub delivery_http: bool,
    // 队列后端：memory|sled
    pub queue_backend: String,
    // 内存队列容量
    pub queue_cap: usize,
    // 内存队列 worker 数
    pub queue_workers: usize,
    // sled 轮询间隔（毫秒）
    pub queue_poll_ms: u64,
}

impl AppConfig {
    #[allow(dead_code)]
    pub fn load_from_env() -> Self {
        Self::load()
    }

    pub fn load() -> Self {
        // 1) 默认值
        let mut cfg = Self::default();

        // 2) 从 TOML 读取（路径可由 AP_CONFIG 指定，默认 config/app.toml）
        let cfg_path = env::var("AP_CONFIG").unwrap_or_else(|_| "config/app.toml".into());
        if Path::new(&cfg_path).exists() {
            if let Ok(txt) = std::fs::read_to_string(&cfg_path) {
                match toml::from_str::<AppConfig>(&txt) {
                    Ok(from_file) => {
                        cfg = AppConfig { ..from_file };
                    }
                    Err(e) => {
                        tracing::warn!(target="config", error=%format!("{e:#}"), path=%cfg_path, "parse toml failed, using defaults");
                    }
                }
            }
        }

        // 3) 环境变量覆盖（若存在）
        if let Ok(v) = env::var("AP_BASE_URL") {
            cfg.base_url = v;
        }
        if let Ok(v) = env::var("AP_LISTEN") {
            cfg.listen_addr = v;
        }
        if let Ok(v) = env::var("AP_SIGN_ENABLE") {
            cfg.sign_enable = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = env::var("AP_SIGN_KEY_ID") {
            cfg.sign_key_id = v;
        }
        if let Ok(v) = env::var("AP_SIGN_SECRET") {
            cfg.sign_shared_secret = v;
        }
        if let Ok(v) = env::var("AP_BACKOFF_BASE_MS") {
            if let Ok(n) = v.parse() {
                cfg.backoff_base_ms = n;
            }
        }
        if let Ok(v) = env::var("AP_BACKOFF_MAX_MS") {
            if let Ok(n) = v.parse() {
                cfg.backoff_max_ms = n;
            }
        }
        if let Ok(v) = env::var("AP_BACKOFF_MAX_RETRIES") {
            if let Ok(n) = v.parse() {
                cfg.backoff_max_retries = n;
            }
        }
        if let Ok(v) = env::var("AP_DEDUP_BACKEND") {
            cfg.dedup_backend = v;
        }
        if let Ok(v) = env::var("AP_SLED_PATH") {
            cfg.sled_path = v;
        }
        if let Ok(v) = env::var("AP_SIGN_MAX_SKEW_SEC") {
            if let Ok(n) = v.parse() {
                cfg.sign_max_skew_sec = n;
            }
        }
        if let Ok(v) = env::var("AP_SIGN_ALG") {
            cfg.sign_alg = v;
        }
        if let Ok(v) = env::var("AP_SIGN_PRIV_KEY_PATH") {
            cfg.sign_priv_key_path = v;
        }
        if let Ok(v) = env::var("AP_HTTP_TIMEOUT_MS") {
            if let Ok(n) = v.parse() {
                cfg.http_timeout_ms = n;
            }
        }
        if let Ok(v) = env::var("AP_DELIVERY_HTTP") {
            cfg.delivery_http = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = env::var("AP_QUEUE_BACKEND") {
            cfg.queue_backend = v;
        }
        if let Ok(v) = env::var("AP_QUEUE_CAP") {
            if let Ok(n) = v.parse() {
                cfg.queue_cap = n;
            }
        }
        if let Ok(v) = env::var("AP_QUEUE_WORKERS") {
            if let Ok(n) = v.parse() {
                cfg.queue_workers = n;
            }
        }
        if let Ok(v) = env::var("AP_QUEUE_POLL_MS") {
            if let Ok(n) = v.parse() {
                cfg.queue_poll_ms = n;
            }
        }

        cfg
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8080".into(),
            listen_addr: "0.0.0.0:8080".into(),
            sign_enable: false,
            sign_key_id: "local#main".into(),
            sign_shared_secret: String::new(),
            backoff_base_ms: 500,
            backoff_max_ms: 10_000,
            backoff_max_retries: 3,
            dedup_backend: "memory".into(),
            sled_path: "./data/dedup.sled".into(),
            sign_max_skew_sec: 300,
            sign_alg: "hmac".into(),
            sign_priv_key_path: String::new(),
            http_timeout_ms: 10_000,
            delivery_http: false,
            queue_backend: "memory".into(),
            queue_cap: 1000,
            queue_workers: 2,
            queue_poll_ms: 500,
        }
    }
}
