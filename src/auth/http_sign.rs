#![allow(dead_code)]
use chrono::Local;
use silent::header::HeaderValue;
use silent::headers::HeaderMap;

/// HTTP 签名算法
#[derive(Clone, Copy, Debug)]
pub enum HttpSignAlgorithm {
    Hs2019,
}

/// 签名输入
#[derive(Clone, Debug)]
pub struct SignInput<'a> {
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub key_id: &'a str,
    pub private_key_pem: Option<&'a str>,
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

/// 验签器接口（Phase VII-B 扩展真实实现）
pub trait HttpVerifier: Send + Sync {
    fn verify(&self, _headers: &HeaderMap) -> VerifyResult {
        VerifyResult::Skipped
    }
}
