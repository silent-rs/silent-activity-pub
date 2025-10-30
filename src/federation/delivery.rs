#![allow(dead_code)]
use chrono::Local;
use std::time::Duration;
use tracing::info;

use crate::auth::http_sign::{HmacSha256Signer, HttpSigner, PlaceholderSigner, SignInput};
use crate::config::AppConfig;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request as HyperRequest, StatusCode as HyperStatus};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::time::Instant;

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
    key_id: String,
    shared_secret: String,
}

impl<S: HttpSigner> LoggingDelivery<S> {
    pub fn new(signer: S, backoff: BackoffPolicy, key_id: String, shared_secret: String) -> Self {
        Self {
            signer,
            backoff,
            key_id,
            shared_secret,
        }
    }
}

#[async_trait::async_trait]
impl<S: HttpSigner + Send + Sync> OutboundDelivery for LoggingDelivery<S> {
    async fn post_activity(&self, inbox_url: &str, body: &str) -> anyhow::Result<()> {
        let sign = self.signer.sign(SignInput {
            method: "post",
            path_and_query: inbox_url,
            key_id: &self.key_id,
            private_key_pem: None,
            shared_secret: Some(&self.shared_secret),
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
    LoggingDelivery::new(
        signer,
        backoff,
        cfg.sign_key_id.clone(),
        cfg.sign_shared_secret.clone(),
    )
}

/// 使用 Hyper 发送带签名的 HTTP POST（当前仅支持 http，不含 TLS）
pub async fn deliver_activity_http(
    cfg: &AppConfig,
    inbox_url: &str,
    body: &str,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let signer = HmacSha256Signer;
    let sign = signer.sign(SignInput {
        method: "post",
        path_and_query: inbox_url,
        key_id: &cfg.sign_key_id,
        private_key_pem: None,
        shared_secret: Some(&cfg.sign_shared_secret),
    });

    // 仅支持 http（非 https）
    let mut http = HttpConnector::new();
    http.enforce_http(true);
    let client = Client::builder(TokioExecutor::new()).build(http);

    let req: HyperRequest<Full<Bytes>> = HyperRequest::post(inbox_url)
        .header(http::header::CONTENT_TYPE, "application/activity+json")
        .header(http::header::DATE, sign.date)
        .header(
            http::header::HeaderName::from_static("signature"),
            sign.signature,
        )
        .body(Full::from(Bytes::from(body.to_owned())))?;

    let resp = client.request(req).await?;
    let status = resp.status();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    if status.is_success() || status == HyperStatus::ACCEPTED {
        info!(target:"delivery", %inbox_url, %elapsed_ms, status=%status.as_u16(), "deliver ok");
        Ok(())
    } else {
        anyhow::bail!("deliver failed: {}", status)
    }
}
