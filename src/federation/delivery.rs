#![allow(dead_code)]
use chrono::Local;
use std::time::Duration;
use tracing::info;

use crate::auth::http_sign::{HmacSha256Signer, HttpSigner, PlaceholderSigner, SignInput};
use crate::config::AppConfig;

/// 重试与退避策略
#[derive(Clone, Debug)]
pub struct BackoffPolicy {
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub max_retries: usize,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            max_retries: 3,
        }
    }
}

/// 出站投递接口（抽象）
#[async_trait::async_trait]
pub trait OutboundDelivery: Send + Sync {
    async fn post_activity(&self, inbox_url: &str, body: &str) -> anyhow::Result<()>;
}

/// 基础占位实现：仅日志打印，不真正发送网络请求
pub struct LoggingDelivery<S: HttpSigner = PlaceholderSigner> {
    signer: S,
    backoff: BackoffPolicy,
}

impl<S: HttpSigner> LoggingDelivery<S> {
    pub fn new(signer: S, backoff: BackoffPolicy) -> Self {
        Self { signer, backoff }
    }
}

#[async_trait::async_trait]
impl<S: HttpSigner + Send + Sync> OutboundDelivery for LoggingDelivery<S> {
    async fn post_activity(&self, inbox_url: &str, body: &str) -> anyhow::Result<()> {
        let sign = self.signer.sign(SignInput {
            method: "post",
            path_and_query: inbox_url,
            key_id: "local#main",
            private_key_pem: None,
            shared_secret: Some("dev-secret"),
        });
        info!(
            target: "delivery",
            %inbox_url,
            date = ?sign.date,
            signature = ?sign.signature,
            time = %Local::now().naive_local(),
            "stub deliver activity: {}",
            body
        );
        Ok(())
    }
}

/// 由配置构建一个占位出站投递器
#[allow(clippy::default_constructed_unit_structs)]
pub fn build_delivery_from_config(cfg: &AppConfig) -> LoggingDelivery<HmacSha256Signer> {
    let signer = HmacSha256Signer;
    let backoff = BackoffPolicy {
        base_delay: Duration::from_millis(cfg.backoff_base_ms),
        max_delay: Duration::from_millis(cfg.backoff_max_ms),
        max_retries: cfg.backoff_max_retries,
    };
    let _ = signer.algorithm();
    LoggingDelivery::new(signer, backoff)
}
