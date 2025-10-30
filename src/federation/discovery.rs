use serde_json::json;
use silent::{header, Request, Response, Result, StatusCode};

use crate::config::AppConfig;

/// WebFinger: /.well-known/webfinger?resource=acct:name@domain
#[silent_openapi::endpoint(
    summary = "WebFinger 查询",
    description = "根据 acct:* 查询 Actor 入口，自描述链接 rel=self 指向 Actor profile"
)]
pub async fn webfinger(mut req: Request) -> Result<Response> {
    let params = req.params().clone();
    let Some(subject) = params.get("resource").cloned() else {
        let mut res = Response::json(&json!({ "error": "missing resource" }));
        res.set_status(StatusCode::BAD_REQUEST);
        return Ok(res);
    };

    let username = subject
        .strip_prefix("acct:")
        .and_then(|s| s.split('@').next())
        .unwrap_or("")
        .to_string();

    let cfg: &AppConfig = req.get_config_uncheck();
    let actor_url = format!("{}/users/{}", cfg.base_url, username);

    // JRD 响应
    let jrd = json!({
        "subject": subject,
        "links": [
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": actor_url
            }
        ]
    });
    let mut res = Response::json(&jrd);
    // WebFinger 规范建议使用 application/jrd+json
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/jrd+json"),
    );
    Ok(res)
}
