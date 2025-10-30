use crate::auth::http_sign::verify_hmac_sha256_headers;
use crate::config::AppConfig;
use crate::observability::metrics::record_inbound;
use serde_json::Value;
use silent::{Request, Response, Result, StatusCode};

/// Shared inbox 和用户 inbox 占位：返回 202
#[silent_openapi::endpoint(
    summary = "inbox 接收占位",
    description = "接受 Activity（未做签名），返回 202"
)]
pub async fn inbox(_req: Request) -> Result<Response> {
    // 验签（可选）
    let req = _req;
    let cfg_owned: AppConfig = req.get_config_uncheck::<AppConfig>().clone();
    if cfg_owned.sign_enable && !cfg_owned.sign_shared_secret.is_empty() {
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
