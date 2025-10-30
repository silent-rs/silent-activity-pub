use crate::auth::http_sign::{verify_date_skew, verify_hmac_sha256_headers};
use crate::config::AppConfig;
use crate::observability::metrics::record_inbound;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use silent::prelude::ReqBody;
use silent::{Request, Response, Result, StatusCode};

/// Shared inbox 和用户 inbox 占位：返回 202
#[silent_openapi::endpoint(
    summary = "inbox 接收占位",
    description = "接受 Activity（未做签名），返回 202"
)]
pub async fn inbox(_req: Request) -> Result<Response> {
    // 验签（可选）
    let mut req = _req;
    let cfg_owned: AppConfig = req.get_config_uncheck::<AppConfig>().clone();
    if cfg_owned.sign_enable && !cfg_owned.sign_shared_secret.is_empty() {
        // 校验 Date 偏移
        if !verify_date_skew(req.headers(), cfg_owned.sign_max_skew_sec) {
            record_inbound("inbox", "unauthorized");
            let mut res = Response::empty();
            res.set_status(StatusCode::UNAUTHORIZED);
            return Ok(res);
        }
        // 如果带有 Digest 头，进行校验（SHA-256）
        let digest_header: Option<String> = req
            .headers()
            .get("digest")
            .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
        if let Some(digest_str) = digest_header {
            // 形如 "SHA-256=base64" 或多项逗号分隔
            let mut expected_opt: Option<&str> = None;
            for kv in digest_str.split(',') {
                let kv = kv.trim();
                if let Some(eq) = kv.find('=') {
                    let (alg, val) = kv.split_at(eq);
                    let val = &val[1..];
                    if alg.trim().eq_ignore_ascii_case("sha-256") {
                        expected_opt = Some(val.trim());
                        break;
                    }
                }
            }
            if let Some(expected) = expected_opt {
                // 读取 body 并恢复
                let body0 = req.take_body();
                let bytes: Bytes = match body0 {
                    ReqBody::Incoming(body) => body
                        .collect()
                        .await
                        .map_err(|_| silent::SilentError::JsonEmpty)?
                        .to_bytes(),
                    ReqBody::Once(b) => b,
                    ReqBody::Empty => Bytes::new(),
                };
                let _ = req.replace_body(ReqBody::Once(bytes.clone()));
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let got = general_purpose::STANDARD.encode(hasher.finalize());
                if got != expected {
                    record_inbound("inbox", "bad_digest");
                    let mut res = Response::empty();
                    res.set_status(StatusCode::BAD_REQUEST);
                    return Ok(res);
                }
            }
        }
        let method = req.method().to_string();
        let path_q = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let ok = verify_hmac_sha256_headers(
            req.headers(),
            &method,
            path_q,
            &cfg_owned.sign_shared_secret,
        );
        record_inbound("inbox", if ok { "ok" } else { "unauthorized" });
        if !ok {
            let mut res = Response::empty();
            res.set_status(StatusCode::UNAUTHORIZED);
            return Ok(res);
        }
    } else {
        record_inbound("inbox", "ok");
    }

    // 简单去重：基于 activity.id
    let mut res = Response::empty();
    if let Ok(val) = {
        let mut req2 = req;
        // 尝试解析为 JSON（不会用于后续业务，仅用于去重）
        req2.json_parse::<Value>().await
    } {
        if let Some(id) = val.get("id").and_then(|v| v.as_str()) {
            if !crate::utils::dedup::record_seen_with_config(id, &cfg_owned) {
                res.headers_mut().insert(
                    silent::header::HeaderName::from_static("x-deduplicated"),
                    silent::header::HeaderValue::from_static("true"),
                );
            }
        }
    }
    res.set_status(StatusCode::ACCEPTED);
    Ok(res)
}
