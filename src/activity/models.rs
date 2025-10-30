use serde_json::json;
use silent::{header, Request, Response, Result};

use crate::config::AppConfig;

/// Actor Profile: /users/<name>
#[silent_openapi::endpoint(
    summary = "获取 Actor Profile",
    description = "返回 ActivityStreams Person，包含 inbox/outbox 链接"
)]
pub async fn actor(req: Request) -> Result<Response> {
    let name: String = req
        .get_path_params("name")
        .unwrap_or_else(|_| "unknown".into());
    let cfg: &AppConfig = req.get_config_uncheck();
    let id = format!("{}/users/{}", cfg.base_url, &name);
    let inbox = format!("{}/users/{}/inbox", cfg.base_url, &name);
    let outbox = format!("{}/users/{}/outbox", cfg.base_url, &name);

    let obj = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1"
        ],
        "id": id,
        "type": "Person",
        "preferredUsername": name,
        "inbox": inbox,
        "outbox": outbox
    });
    let mut res = Response::json(&obj);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/activity+json"),
    );
    Ok(res)
}
