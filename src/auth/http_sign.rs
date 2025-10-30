#![allow(dead_code)]
use base64::{engine::general_purpose, Engine as _};
use chrono::Local;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use silent::header;
use silent::header::HeaderValue;
use silent::headers::HeaderMap;

/// HTTP 签名算法
#[derive(Clone, Copy, Debug)]
pub enum HttpSignAlgorithm {
    Hs2019,
    HmacSha256,
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
