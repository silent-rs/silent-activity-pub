#![allow(dead_code)]
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use chrono::Local;
use ed25519_dalek::Signer as _;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use hyper::{Request as HyperRequest, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use lru::LruCache;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use sha2::Sha256;
use silent::header;
use silent::header::HeaderValue;
use silent::headers::HeaderMap;
use std::num::NonZeroUsize;

/// HTTP 签名算法
#[derive(Clone, Copy, Debug)]
pub enum HttpSignAlgorithm {
    Hs2019,
    HmacSha256,
    RsaSha256,
    Ed25519,
}

/// 签名输入
#[derive(Clone, Debug)]
pub struct SignInput<'a> {
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub key_id: &'a str,
    pub private_key_pem: Option<&'a str>,
    pub shared_secret: Option<&'a str>,
}

/// 签名输出（需要设置到请求头）
#[derive(Clone, Debug)]
pub struct SignOutput {
    pub date: HeaderValue,
    pub signature: HeaderValue,
}

/// 签名器接口（可扩展不同算法/实现）
pub trait HttpSigner: Send + Sync {
    fn algorithm(&self) -> HttpSignAlgorithm;
    fn sign(&self, input: SignInput) -> SignOutput;
}

/// 占位实现：不进行真实加密，只生成占位 Signature 头，便于端到端联调
#[derive(Clone, Debug, Default)]
pub struct PlaceholderSigner;

impl HttpSigner for PlaceholderSigner {
    fn algorithm(&self) -> HttpSignAlgorithm {
        HttpSignAlgorithm::Hs2019
    }

    fn sign(&self, input: SignInput) -> SignOutput {
        let date_str = Local::now().to_rfc2822();
        let sig_value = format!(
            "keyId=\"{}\",algorithm=\"hs2019\",headers=\"(request-target) date\",signature=\"{}\"",
            input.key_id, "PLACEHOLDER"
        );

        SignOutput {
            date: HeaderValue::from_str(date_str.as_str())
                .unwrap_or_else(|_| HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 +0000")),
            signature: HeaderValue::from_str(sig_value.as_str())
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        }
    }
}

/// 入站验签结果
#[derive(Clone, Debug)]
pub enum VerifyResult {
    Passed,
    Skipped,
}

/// 基于 HMAC-SHA256 的签名实现（配置共享密钥）
#[derive(Clone, Debug, Default)]
pub struct HmacSha256Signer;

impl HttpSigner for HmacSha256Signer {
    fn algorithm(&self) -> HttpSignAlgorithm {
        HttpSignAlgorithm::HmacSha256
    }

    fn sign(&self, input: SignInput) -> SignOutput {
        let date_str = Local::now().to_rfc2822();
        let signing_string = format!(
            "(request-target): {} {}\ndate: {}",
            input.method.to_lowercase(),
            input.path_and_query,
            date_str
        );
        let secret = input.shared_secret.unwrap_or("");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .unwrap_or_else(|_| Hmac::<Sha256>::new_from_slice(&[0u8; 0]).unwrap());
        mac.update(signing_string.as_bytes());
        let sig_bytes = mac.finalize().into_bytes();
        let sig_b64 = general_purpose::STANDARD.encode(sig_bytes);
        let sig_value = format!(
            "keyId=\"{}\",algorithm=\"hmac-sha256\",headers=\"(request-target) date\",signature=\"{}\"",
            input.key_id, sig_b64
        );
        SignOutput {
            date: HeaderValue::from_str(date_str.as_str())
                .unwrap_or_else(|_| HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 +0000")),
            signature: HeaderValue::from_str(sig_value.as_str())
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        }
    }
}

/// hs2019 RSA-SHA256 签名器
pub struct RsaSha256Signer {
    private_key: rsa::RsaPrivateKey,
}

impl RsaSha256Signer {
    pub fn from_pkcs8_pem(pem: &str) -> anyhow::Result<Self> {
        use rsa::pkcs8::DecodePrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem)?;
        Ok(Self { private_key: key })
    }
}

impl HttpSigner for RsaSha256Signer {
    fn algorithm(&self) -> HttpSignAlgorithm {
        HttpSignAlgorithm::RsaSha256
    }
    fn sign(&self, input: SignInput) -> SignOutput {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256 as Sha2;
        let date_str = Local::now().to_rfc2822();
        let signing_string = format!(
            "(request-target): {} {}\ndate: {}",
            input.method.to_lowercase(),
            input.path_and_query,
            date_str
        );
        let key = SigningKey::<Sha2>::new(self.private_key.clone());
        let sig = key.sign(signing_string.as_bytes());
        let sig_b64 = general_purpose::STANDARD.encode(sig.to_bytes());
        let sig_value = format!(
            "keyId=\"{}\",algorithm=\"hs2019\",headers=\"(request-target) date\",signature=\"{}\"",
            input.key_id, sig_b64
        );
        SignOutput {
            date: HeaderValue::from_str(date_str.as_str())
                .unwrap_or_else(|_| HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 +0000")),
            signature: HeaderValue::from_str(sig_value.as_str())
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        }
    }
}

/// hs2019 Ed25519 签名器
pub struct Ed25519Signer(ed25519_dalek::SigningKey);

impl Ed25519Signer {
    pub fn from_pkcs8_pem(pem: &str) -> anyhow::Result<Self> {
        use pkcs8::DecodePrivateKey;
        let key = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)?;
        Ok(Self(key))
    }
}

impl HttpSigner for Ed25519Signer {
    fn algorithm(&self) -> HttpSignAlgorithm {
        HttpSignAlgorithm::Ed25519
    }
    fn sign(&self, input: SignInput) -> SignOutput {
        let date_str = Local::now().to_rfc2822();
        let signing_string = format!(
            "(request-target): {} {}\ndate: {}",
            input.method.to_lowercase(),
            input.path_and_query,
            date_str
        );
        let sig = self.0.sign(signing_string.as_bytes());
        let sig_b64 = general_purpose::STANDARD.encode(sig.to_bytes());
        let sig_value = format!(
            "keyId=\"{}\",algorithm=\"hs2019\",headers=\"(request-target) date\",signature=\"{}\"",
            input.key_id, sig_b64
        );
        SignOutput {
            date: HeaderValue::from_str(date_str.as_str())
                .unwrap_or_else(|_| HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 +0000")),
            signature: HeaderValue::from_str(sig_value.as_str())
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        }
    }
}

/// 验签器接口（Phase VII-B 扩展真实实现）
pub trait HttpVerifier: Send + Sync {
    fn verify(&self, _headers: &HeaderMap) -> VerifyResult {
        VerifyResult::Skipped
    }
}

fn parse_signature_header(value: &HeaderValue) -> Option<(String, String)> {
    let s = value.to_str().ok()?;
    // very naive parser: keyId="..",signature=".."
    let mut key_id = String::new();
    let mut signature = String::new();
    for part in s.split(',') {
        let kv: Vec<&str> = part.splitn(2, '=').collect();
        if kv.len() != 2 {
            continue;
        }
        let k = kv[0].trim();
        let v = kv[1].trim().trim_matches('"');
        match k {
            "keyId" => key_id = v.to_string(),
            "signature" => signature = v.to_string(),
            _ => {}
        }
    }
    if key_id.is_empty() || signature.is_empty() {
        None
    } else {
        Some((key_id, signature))
    }
}

pub fn verify_hmac_sha256_headers(
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    shared_secret: &str,
) -> bool {
    let sig_header = match headers.get("signature") {
        Some(v) => v,
        None => return false,
    };
    let date = match headers.get(header::DATE) {
        Some(v) => v.to_str().ok().unwrap_or(""),
        None => return false,
    };
    let (_key_id, sig_b64) = match parse_signature_header(sig_header) {
        Some(t) => t,
        None => return false,
    };
    let signing_string = format!(
        "(request-target): {} {}\ndate: {}",
        method.to_lowercase(),
        path_and_query,
        date
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret.as_bytes())
        .unwrap_or_else(|_| Hmac::<Sha256>::new_from_slice(&[0u8; 0]).unwrap());
    mac.update(signing_string.as_bytes());
    let expected = general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    expected == sig_b64
}

/// 校验 Date 与当前时间偏移是否在允许范围内
pub fn verify_date_skew(headers: &HeaderMap, max_skew_sec: u64) -> bool {
    let date_val = match headers.get(header::DATE) {
        Some(v) => v,
        None => return false,
    };
    let date_str = match date_val.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    // 解析 RFC2822 日期
    let parsed = match chrono::DateTime::parse_from_rfc2822(date_str) {
        Ok(dt) => dt,
        Err(_) => return false,
    };
    let sent = parsed.with_timezone(&chrono::Utc).timestamp();
    let now = chrono::Utc::now().timestamp();
    let skew = (now - sent).unsigned_abs();
    skew <= max_skew_sec
}

// ========== hs2019 inbound verify (RSA) ==========

static PUBKEY_CACHE: Lazy<Mutex<LruCache<String, RsaPublicKey>>> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(1024).unwrap())));

async fn http_get_bytes(url: &str) -> anyhow::Result<Bytes> {
    if url.starts_with("https://") {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("native roots")
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        let req = HyperRequest::get(url)
            .header(
                silent::header::ACCEPT,
                "application/activity+json, application/ld+json",
            )
            .body(http_body_util::Empty::<bytes::Bytes>::new())?;
        let resp = client.request(req).await?;
        if resp.status() != StatusCode::OK {
            anyhow::bail!("status {}", resp.status());
        }
        let body = resp.into_body().collect().await?.to_bytes();
        Ok(body)
    } else {
        let mut http = HttpConnector::new();
        http.enforce_http(true);
        let client = Client::builder(TokioExecutor::new()).build(http);
        let req = HyperRequest::get(url)
            .header(
                silent::header::ACCEPT,
                "application/activity+json, application/ld+json",
            )
            .body(http_body_util::Empty::<bytes::Bytes>::new())?;
        let resp = client.request(req).await?;
        if resp.status() != StatusCode::OK {
            anyhow::bail!("status {}", resp.status());
        }
        let body = resp.into_body().collect().await?.to_bytes();
        Ok(body)
    }
}

async fn fetch_rsa_pubkey(key_id: &str) -> anyhow::Result<RsaPublicKey> {
    // 尝试直接获取 keyId 文档，解析 publicKeyPem
    let bytes = http_get_bytes(key_id).await?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)?;
    let pem = if let Some(p) = v.get("publicKeyPem").and_then(|s| s.as_str()) {
        p.to_string()
    } else if let Some(obj) = v.get("publicKey").and_then(|o| o.as_object()) {
        obj.get("publicKeyPem")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        "".into()
    };
    if pem.is_empty() {
        anyhow::bail!("no publicKeyPem in document")
    }
    let pk = RsaPublicKey::from_public_key_pem(&pem)?;
    Ok(pk)
}

pub async fn verify_hs2019_headers_async(
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
) -> bool {
    let sig_header = match headers.get("signature") {
        Some(v) => v,
        None => return false,
    };
    let (key_id, sig_b64) = match parse_signature_header(sig_header) {
        Some(t) => t,
        None => return false,
    };
    // try cache hit
    if let Some(pk) = {
        let mut c = PUBKEY_CACHE.lock();
        c.get(&key_id).cloned()
    } {
        return verify_rsa_sig(headers, method, path_and_query, &sig_b64, pk);
    }
    // fetch without holding the lock
    let fetched = match fetch_rsa_pubkey(&key_id).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(target="verify", error=%format!("{e:#}"), key_id=%key_id, "fetch public key failed");
            return false;
        }
    };
    {
        let mut c2 = PUBKEY_CACHE.lock();
        c2.put(key_id.clone(), fetched.clone());
    }
    verify_rsa_sig(headers, method, path_and_query, &sig_b64, fetched)
}

fn verify_rsa_sig(
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    sig_b64: &str,
    pk: RsaPublicKey,
) -> bool {
    // build signing string
    let date = match headers.get(header::DATE) {
        Some(v) => v.to_str().ok().unwrap_or(""),
        None => return false,
    };
    let signing_string = format!(
        "(request-target): {} {}\ndate: {}",
        method.to_lowercase(),
        path_and_query,
        date
    );
    // decode sig
    let sig = match base64::engine::general_purpose::STANDARD.decode(sig_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // verify pkcs1v15 sha256
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    let vk = VerifyingKey::<sha2::Sha256>::new(pk);
    if let Ok(sig_obj) = rsa::pkcs1v15::Signature::try_from(sig.as_slice()) {
        vk.verify(signing_string.as_bytes(), &sig_obj).is_ok()
    } else {
        false
    }
}
