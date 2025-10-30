#![allow(dead_code)]
use crate::observability::metrics::record_delivery;
use chrono::Local;
use std::time::Duration;
use tracing::info;

use crate::auth::http_sign::{
    Ed25519Signer, HmacSha256Signer, HttpSigner, PlaceholderSigner, RsaSha256Signer, SignInput,
};
use crate::config::AppConfig;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request as HyperRequest, StatusCode as HyperStatus};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use sha2::{Digest, Sha256};
use std::time::Instant;
use tokio::time::sleep;

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

/// 动态签名投递器（使用 trait 对象便于按配置切换算法）
pub struct DynDelivery {
    signer: Box<dyn HttpSigner + Send + Sync>,
    backoff: BackoffPolicy,
    key_id: String,
    shared_secret: String,
}

impl DynDelivery {
    pub fn new(
        signer: Box<dyn HttpSigner + Send + Sync>,
        backoff: BackoffPolicy,
        key_id: String,
        shared_secret: String,
    ) -> Self {
        Self {
            signer,
            backoff,
            key_id,
            shared_secret,
        }
    }
}

#[async_trait::async_trait]
impl OutboundDelivery for DynDelivery {
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
            "stub deliver activity(dyn): {}",
            body
        );
        Ok(())
    }
}

/// 由配置构建一个占位出站投递器
#[allow(clippy::default_constructed_unit_structs)]
pub fn build_delivery_from_config(cfg: &AppConfig) -> DynDelivery {
    let signer_box: Box<dyn HttpSigner> = match cfg.sign_alg.to_lowercase().as_str() {
        "rsa" => {
            if !cfg.sign_priv_key_path.is_empty() {
                match std::fs::read_to_string(&cfg.sign_priv_key_path) {
                    Ok(pem) => match RsaSha256Signer::from_pkcs8_pem(&pem) {
                        Ok(s) => Box::new(s),
                        Err(e) => {
                            tracing::warn!(target="sign", error=%format!("{e:#}"), "load RSA key failed, fallback to HMAC");
                            Box::new(HmacSha256Signer)
                        }
                    },
                    Err(e) => {
                        tracing::warn!(target="sign", error=%format!("{e:#}"), "read RSA key file failed, fallback to HMAC");
                        Box::new(HmacSha256Signer)
                    }
                }
            } else {
                Box::new(HmacSha256Signer)
            }
        }
        "ed25519" => {
            if !cfg.sign_priv_key_path.is_empty() {
                match std::fs::read_to_string(&cfg.sign_priv_key_path) {
                    Ok(pem) => match Ed25519Signer::from_pkcs8_pem(&pem) {
                        Ok(s) => Box::new(s),
                        Err(e) => {
                            tracing::warn!(target="sign", error=%format!("{e:#}"), "load Ed25519 key failed, fallback to HMAC");
                            Box::new(HmacSha256Signer)
                        }
                    },
                    Err(e) => {
                        tracing::warn!(target="sign", error=%format!("{e:#}"), "read Ed25519 key file failed, fallback to HMAC");
                        Box::new(HmacSha256Signer)
                    }
                }
            } else {
                Box::new(HmacSha256Signer)
            }
        }
        _ => Box::new(HmacSha256Signer),
    };
    let backoff = BackoffPolicy {
        base_delay: Duration::from_millis(cfg.backoff_base_ms),
        max_delay: Duration::from_millis(cfg.backoff_max_ms),
        max_retries: cfg.backoff_max_retries,
    };
    let _ = signer_box.algorithm();
    DynDelivery::new(
        signer_box,
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

    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let idem = general_purpose::STANDARD.encode(hasher.finalize());

    let req: HyperRequest<Full<Bytes>> = HyperRequest::post(inbox_url)
        .header(http::header::CONTENT_TYPE, "application/activity+json")
        .header(http::header::DATE, sign.date)
        .header(
            http::header::HeaderName::from_static("signature"),
            sign.signature,
        )
        .header(
            http::header::HeaderName::from_static("idempotency-key"),
            idem,
        )
        .body(Full::from(Bytes::from(body.to_owned())))?;

    let resp = client.request(req).await?;
    let status = resp.status();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    if status.is_success() || status == HyperStatus::ACCEPTED {
        info!(target:"delivery", %inbox_url, %elapsed_ms, status=%status.as_u16(), "deliver ok");
        record_delivery("http", true, status.as_u16(), elapsed_ms);
        Ok(())
    } else {
        record_delivery("http", false, status.as_u16(), elapsed_ms);
        anyhow::bail!("deliver failed: {}", status)
    }
}

/// 根据 URL 选择 HTTP/HTTPS 连接器，并按退避策略进行重试
pub async fn deliver_activity(cfg: &AppConfig, inbox_url: &str, body: &str) -> anyhow::Result<()> {
    let max_retries = cfg.backoff_max_retries;
    for attempt in 0..=max_retries {
        let start = Instant::now();
        // 选择 connector
        let is_https = inbox_url.starts_with("https://");
        let result = if is_https {
            // https 客户端（webpki 根证书）
            let https = HttpsConnectorBuilder::new()
                .with_native_roots()
                .expect("load native roots")
                .https_only()
                .enable_http1()
                .enable_http2()
                .build();
            let client = Client::builder(TokioExecutor::new()).build(https);

            let signer = HmacSha256Signer;
            let sign = signer.sign(SignInput {
                method: "post",
                path_and_query: inbox_url,
                key_id: &cfg.sign_key_id,
                private_key_pem: None,
                shared_secret: Some(&cfg.sign_shared_secret),
            });

            let mut hasher = Sha256::new();
            hasher.update(body.as_bytes());
            let idem = general_purpose::STANDARD.encode(hasher.finalize());

            let req: HyperRequest<Full<Bytes>> = HyperRequest::post(inbox_url)
                .header(http::header::CONTENT_TYPE, "application/activity+json")
                .header(http::header::DATE, sign.date)
                .header(
                    http::header::HeaderName::from_static("signature"),
                    sign.signature,
                )
                .header(
                    http::header::HeaderName::from_static("idempotency-key"),
                    idem,
                )
                .body(Full::from(Bytes::from(body.to_owned())))?;
            let resp = client.request(req).await;
            resp.map(|r| (r.status(), start.elapsed()))
        } else {
            // http 客户端（明文）
            let mut http = HttpConnector::new();
            http.enforce_http(true);
            let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(http);

            let signer = HmacSha256Signer;
            let sign = signer.sign(SignInput {
                method: "post",
                path_and_query: inbox_url,
                key_id: &cfg.sign_key_id,
                private_key_pem: None,
                shared_secret: Some(&cfg.sign_shared_secret),
            });

            let mut hasher = Sha256::new();
            hasher.update(body.as_bytes());
            let idem = general_purpose::STANDARD.encode(hasher.finalize());

            let req: HyperRequest<Full<Bytes>> = HyperRequest::post(inbox_url)
                .header(http::header::CONTENT_TYPE, "application/activity+json")
                .header(http::header::DATE, sign.date)
                .header(
                    http::header::HeaderName::from_static("signature"),
                    sign.signature,
                )
                .header(
                    http::header::HeaderName::from_static("idempotency-key"),
                    idem,
                )
                .body(Full::from(Bytes::from(body.to_owned())))?;
            let resp = client.request(req).await;
            resp.map(|r| (r.status(), start.elapsed()))
        };

        match result {
            Ok((status, elapsed)) if status.is_success() || status == HyperStatus::ACCEPTED => {
                info!(target:"delivery", %inbox_url, elapsed_ms=%elapsed.as_millis(), status=%status.as_u16(), attempt, "deliver ok");
                let scheme = if is_https { "https" } else { "http" };
                record_delivery(scheme, true, status.as_u16(), elapsed.as_millis() as u64);
                return Ok(());
            }
            Ok((status, elapsed)) => {
                info!(target:"delivery", %inbox_url, elapsed_ms=%elapsed.as_millis(), status=%status.as_u16(), attempt, "deliver failed, retrying if allowed");
                let scheme = if is_https { "https" } else { "http" };
                record_delivery(scheme, false, status.as_u16(), elapsed.as_millis() as u64);
            }
            Err(e) => {
                info!(target:"delivery", %inbox_url, attempt, error=%format!("{e:#}").as_str(), "deliver error, retrying if allowed");
                let scheme = if is_https { "https" } else { "http" };
                // 记录为 code=0 的异常
                record_delivery(scheme, false, 0, start.elapsed().as_millis() as u64);
            }
        }

        if attempt < max_retries {
            // 指数退避：base * 2^attempt，上限为 max
            let pow = 1u64 << (attempt.min(16) as u32);
            let base = cfg.backoff_base_ms.saturating_mul(pow);
            let delay_ms = base.min(cfg.backoff_max_ms);
            sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    anyhow::bail!("deliver exhausted retries")
}
