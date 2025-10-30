#![allow(dead_code)]
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use chrono::Local;
use ed25519_dalek::Signer as _;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
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

#[derive(Debug, Clone)]
struct SignatureParams {
    key_id: String,
    algorithm: Option<String>,
    headers: Vec<String>,
    signature_b64: String,
    created: Option<i64>,
    expires: Option<i64>,
}

fn parse_signature_header_full(value: &HeaderValue) -> Option<SignatureParams> {
    let s = value.to_str().ok()?;
    let mut key_id = String::new();
    let mut algorithm: Option<String> = None;
    let mut headers: Option<Vec<String>> = None;
    let mut signature_b64 = String::new();
    let mut created: Option<i64> = None;
    let mut expires: Option<i64> = None;

    for part in s.split(',') {
        let part = part.trim();
        let mut kv = part.splitn(2, '=');
        let k = kv.next().unwrap_or("").trim();
        let v_raw = kv.next().unwrap_or("").trim();
        let v = v_raw.trim_matches('\"');
        match k {
            "keyId" => key_id = v.to_string(),
            "algorithm" => algorithm = Some(v.to_ascii_lowercase()),
            "headers" => {
                let list = v
                    .split_whitespace()
                    .map(|h| h.to_ascii_lowercase())
                    .collect::<Vec<_>>();
                if !list.is_empty() {
                    headers = Some(list);
                }
            }
            "signature" => signature_b64 = v.to_string(),
            "created" => {
                if let Ok(n) = v.trim_matches('\"').parse::<i64>() {
                    created = Some(n)
                }
            }
            "expires" => {
                if let Ok(n) = v.trim_matches('\"').parse::<i64>() {
                    expires = Some(n)
                }
            }
            _ => {}
        }
    }
    if key_id.is_empty() || signature_b64.is_empty() {
        None
    } else {
        Some(SignatureParams {
            key_id,
            algorithm,
            headers: headers.unwrap_or_else(|| vec!["(request-target)".into(), "date".into()]),
            signature_b64,
            created,
            expires,
        })
    }
}

fn build_signing_string(
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    params: &SignatureParams,
) -> Option<String> {
    let mut lines: Vec<String> = Vec::with_capacity(params.headers.len());
    for name in &params.headers {
        let lname = name.to_ascii_lowercase();
        if lname == "(request-target)" {
            lines.push(format!(
                "(request-target): {} {}",
                method.to_lowercase(),
                path_and_query
            ));
        } else if lname == "(created)" {
            let created = params.created?;
            lines.push(format!("(created): {}", created));
        } else if lname == "(expires)" {
            let expires = params.expires?;
            lines.push(format!("(expires): {}", expires));
        } else {
            let hname = match silent::header::HeaderName::from_bytes(lname.as_bytes()) {
                Ok(n) => n,
                Err(_) => return None,
            };
            let val = headers.get(hname)?;
            let val_str = val.to_str().ok()?;
            lines.push(format!("{}: {}", lname, val_str));
        }
    }
    Some(lines.join("\n"))
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
    max_skew_sec: u64,
) -> bool {
    let sig_header = match headers.get("signature") {
        Some(v) => v,
        None => return false,
    };
    let params = match parse_signature_header_full(sig_header) {
        Some(p) => p,
        None => return false,
    };
    if !validate_sig_time(&params, max_skew_sec) {
        return false;
    }
    let signing_string = match build_signing_string(headers, method, path_and_query, &params) {
        Some(s) => s,
        None => return false,
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret.as_bytes())
        .unwrap_or_else(|_| Hmac::<Sha256>::new_from_slice(&[0u8; 0]).unwrap());
    mac.update(signing_string.as_bytes());
    let expected = general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    expected == params.signature_b64
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

static ED25519_PUBKEY_CACHE: Lazy<Mutex<LruCache<String, Ed25519VerifyingKey>>> =
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

async fn fetch_ed25519_pubkey(key_id: &str) -> anyhow::Result<Ed25519VerifyingKey> {
    // 获取 keyId 文档，优先解析 publicKeyPem（SPKI/PEM），其次尝试 publicKeyMultibase 或 publicKeyBase58
    let bytes = http_get_bytes(key_id).await?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)?;
    // 1) publicKeyPem
    if let Some(pem) = v.get("publicKeyPem").and_then(|s| s.as_str()).or_else(|| {
        v.get("publicKey")
            .and_then(|o| o.get("publicKeyPem"))
            .and_then(|s| s.as_str())
    }) {
        let vk = Ed25519VerifyingKey::from_public_key_pem(pem)?;
        return Ok(vk);
    }
    // 2) publicKeyMultibase（常见为 base58-btc，以 'z' 前缀）
    if let Some(mb) = v
        .get("publicKeyMultibase")
        .and_then(|s| s.as_str())
        .or_else(|| {
            v.get("publicKey")
                .and_then(|o| o.get("publicKeyMultibase"))
                .and_then(|s| s.as_str())
        })
    {
        let (_base, data) = multibase::decode(mb)?; // 返回 Vec<u8>
        let arr: [u8; 32] = data
            .try_into()
            .map_err(|_| anyhow::anyhow!("ed25519 pubkey length invalid"))?;
        let vk = Ed25519VerifyingKey::from_bytes(&arr)?;
        return Ok(vk);
    }
    // 3) publicKeyBase58（非 multibase，直接 base58 编码）
    if let Some(b58) = v
        .get("publicKeyBase58")
        .and_then(|s| s.as_str())
        .or_else(|| {
            v.get("publicKey")
                .and_then(|o| o.get("publicKeyBase58"))
                .and_then(|s| s.as_str())
        })
    {
        let data = bs58::decode(b58).into_vec()?;
        let arr: [u8; 32] = data
            .try_into()
            .map_err(|_| anyhow::anyhow!("ed25519 pubkey length invalid"))?;
        let vk = Ed25519VerifyingKey::from_bytes(&arr)?;
        return Ok(vk);
    }
    anyhow::bail!("no ed25519 public key found")
}

/// 综合验签：按 Signature 参数与 key 文档自动选择 RSA 或 Ed25519
pub async fn verify_hs2019_auto_headers_async(
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    max_skew_sec: u64,
) -> bool {
    let sig_header = match headers.get("signature") {
        Some(v) => v,
        None => return false,
    };
    let params = match parse_signature_header_full(sig_header) {
        Some(p) => p,
        None => return false,
    };
    if !validate_sig_time(&params, max_skew_sec) {
        return false;
    }
    let alg_hint = params.algorithm.clone().unwrap_or_else(|| "hs2019".into());
    let signing_string = match build_signing_string(headers, method, path_and_query, &params) {
        Some(s) => s,
        None => return false,
    };

    // 先根据缓存尝试
    if alg_hint.contains("rsa") || alg_hint == "hs2019" {
        if let Some(pk) = {
            let mut c = PUBKEY_CACHE.lock();
            c.get(&params.key_id).cloned()
        } {
            if verify_rsa_sig_with_string(&signing_string, &params.signature_b64, pk) {
                return true;
            }
        }
    }
    if alg_hint.contains("ed25519") || alg_hint == "hs2019" {
        if let Some(vk) = {
            let mut c = ED25519_PUBKEY_CACHE.lock();
            c.get(&params.key_id).cloned()
        } {
            if verify_ed25519_sig_with_string(&signing_string, &params.signature_b64, vk) {
                return true;
            }
        }
    }

    // 缓存未命中或失败，拉取一次文档并判定 key 类型
    let bytes = match http_get_bytes(&params.key_id).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(target="verify", error=%format!("{e:#}"), key_id=%params.key_id, "fetch key document failed");
            return false;
        }
    };
    let v: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target="verify", error=%format!("{e:#}"), key_id=%params.key_id, "parse key document failed");
            return false;
        }
    };

    // 1) 尝试 publicKeyPem → 先当 RSA，再当 Ed25519（SPKI/PEM）
    let pem_opt = v
        .get("publicKeyPem")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("publicKey")
                .and_then(|o| o.get("publicKeyPem"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        });
    if let Some(pem) = pem_opt {
        // RSA
        if let Ok(pk) = RsaPublicKey::from_public_key_pem(&pem) {
            {
                let mut c = PUBKEY_CACHE.lock();
                c.put(params.key_id.clone(), pk.clone());
            }
            return verify_rsa_sig_with_string(&signing_string, &params.signature_b64, pk);
        }
        // Ed25519
        if let Ok(vk) = Ed25519VerifyingKey::from_public_key_pem(&pem) {
            {
                let mut c = ED25519_PUBKEY_CACHE.lock();
                c.put(params.key_id.clone(), vk);
            }
            return verify_ed25519_sig_with_string(&signing_string, &params.signature_b64, vk);
        }
    }

    // 2) publicKeyMultibase → Ed25519
    let mb_opt = v
        .get("publicKeyMultibase")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("publicKey")
                .and_then(|o| o.get("publicKeyMultibase"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        });
    if let Some(mb) = mb_opt {
        if let Ok((_base, data)) = multibase::decode(mb) {
            if let Ok(arr) = <[u8; 32]>::try_from(data.as_slice()) {
                if let Ok(vk) = Ed25519VerifyingKey::from_bytes(&arr) {
                    {
                        let mut c = ED25519_PUBKEY_CACHE.lock();
                        c.put(params.key_id.clone(), vk);
                    }
                    return verify_ed25519_sig_with_string(
                        &signing_string,
                        &params.signature_b64,
                        vk,
                    );
                }
            }
        }
    }

    // 3) publicKeyBase58 → Ed25519
    let b58_opt = v
        .get("publicKeyBase58")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("publicKey")
                .and_then(|o| o.get("publicKeyBase58"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        });
    if let Some(b58) = b58_opt {
        if let Ok(data) = bs58::decode(&b58).into_vec() {
            if let Ok(arr) = <[u8; 32]>::try_from(data.as_slice()) {
                if let Ok(vk) = Ed25519VerifyingKey::from_bytes(&arr) {
                    {
                        let mut c = ED25519_PUBKEY_CACHE.lock();
                        c.put(params.key_id.clone(), vk);
                    }
                    return verify_ed25519_sig_with_string(
                        &signing_string,
                        &params.signature_b64,
                        vk,
                    );
                }
            }
        }
    }

    false
}

fn validate_sig_time(params: &SignatureParams, max_skew_sec: u64) -> bool {
    let now = chrono::Utc::now().timestamp();
    if let Some(c) = params.created {
        let skew = (now - c).unsigned_abs();
        if skew > max_skew_sec {
            return false;
        }
    }
    if let Some(e) = params.expires {
        // 当前时间不得晚于 expires + 容忍偏移
        if now > e + max_skew_sec as i64 {
            return false;
        }
    }
    if let (Some(c), Some(e)) = (params.created, params.expires) {
        if c > e + max_skew_sec as i64 {
            return false;
        }
    }
    true
}

pub async fn verify_hs2019_headers_async(
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    max_skew_sec: u64,
) -> bool {
    let sig_header = match headers.get("signature") {
        Some(v) => v,
        None => return false,
    };
    let params = match parse_signature_header_full(sig_header) {
        Some(p) => p,
        None => return false,
    };
    if !validate_sig_time(&params, max_skew_sec) {
        return false;
    }
    let signing_string = match build_signing_string(headers, method, path_and_query, &params) {
        Some(s) => s,
        None => return false,
    };
    // try cache hit
    if let Some(pk) = {
        let mut c = PUBKEY_CACHE.lock();
        c.get(&params.key_id).cloned()
    } {
        return verify_rsa_sig_with_string(&signing_string, &params.signature_b64, pk);
    }
    // fetch without holding the lock
    let fetched = match fetch_rsa_pubkey(&params.key_id).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(target="verify", error=%format!("{e:#}"), key_id=%params.key_id, "fetch public key failed");
            return false;
        }
    };
    {
        let mut c2 = PUBKEY_CACHE.lock();
        c2.put(params.key_id.clone(), fetched.clone());
    }
    verify_rsa_sig_with_string(&signing_string, &params.signature_b64, fetched)
}

fn verify_rsa_sig_with_string(signing_string: &str, sig_b64: &str, pk: RsaPublicKey) -> bool {
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

// ========== hs2019 inbound verify (Ed25519) ==========

pub async fn verify_hs2019_ed25519_headers_async(
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    max_skew_sec: u64,
) -> bool {
    let sig_header = match headers.get("signature") {
        Some(v) => v,
        None => return false,
    };
    let params = match parse_signature_header_full(sig_header) {
        Some(p) => p,
        None => return false,
    };
    if !validate_sig_time(&params, max_skew_sec) {
        return false;
    }
    let signing_string = match build_signing_string(headers, method, path_and_query, &params) {
        Some(s) => s,
        None => return false,
    };
    // cache
    if let Some(vk) = {
        let mut c = ED25519_PUBKEY_CACHE.lock();
        c.get(&params.key_id).cloned()
    } {
        return verify_ed25519_sig_with_string(&signing_string, &params.signature_b64, vk);
    }
    // fetch
    let fetched = match fetch_ed25519_pubkey(&params.key_id).await {
        Ok(vk) => vk,
        Err(e) => {
            tracing::warn!(target="verify", error=%format!("{e:#}"), key_id=%params.key_id, "fetch ed25519 public key failed");
            return false;
        }
    };
    {
        let mut c2 = ED25519_PUBKEY_CACHE.lock();
        c2.put(params.key_id.clone(), fetched);
    }
    verify_ed25519_sig_with_string(&signing_string, &params.signature_b64, fetched)
}

fn verify_ed25519_sig_with_string(
    signing_string: &str,
    sig_b64: &str,
    vk: Ed25519VerifyingKey,
) -> bool {
    // decode sig
    let sig = match base64::engine::general_purpose::STANDARD.decode(sig_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = match ed25519_dalek::Signature::from_slice(&sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify_strict(signing_string.as_bytes(), &sig).is_ok()
}
