use crate::auth::http_sign::verify_hmac_sha256_headers;
use crate::config::AppConfig;
use crate::observability::metrics::record_inbound;
use silent::{Request, Response, Result, StatusCode};

/// Shared inbox 和用户 inbox 占位：返回 202
#[silent_openapi::endpoint(
    summary = "inbox 接收占位",
    description = "接受 Activity（未做签名），返回 202"
)]
pub async fn inbox(_req: Request) -> Result<Response> {
    // 验签（可选）
    let req = _req;
    let cfg: &AppConfig = req.get_config_uncheck();
    if cfg.sign_enable && !cfg.sign_shared_secret.is_empty() {
        let method = req.method().to_string();
        let path_q = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let ok =
            verify_hmac_sha256_headers(req.headers(), &method, path_q, &cfg.sign_shared_secret);
        record_inbound("inbox", ok);
        if !ok {
            let mut res = Response::empty();
            res.set_status(StatusCode::UNAUTHORIZED);
            return Ok(res);
        }
    } else {
        record_inbound("inbox", true);
    }

    let mut res = Response::empty();
    res.set_status(StatusCode::ACCEPTED);
    Ok(res)
}
