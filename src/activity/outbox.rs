use serde_json::json;
use silent::{header, Request, Response, Result};

use crate::config::AppConfig;

#[silent_openapi::endpoint(
    summary = "获取 Outbox",
    description = "返回 Actor 的 OrderedCollection（占位空集合）"
)]
pub async fn outbox(req: Request) -> Result<Response> {
    let name: String = req
        .get_path_params("name")
        .unwrap_or_else(|_| "unknown".into());
    let cfg: &AppConfig = req.get_config_uncheck();
    let id = format!("{}/users/{}/outbox", cfg.base_url, &name);
    let oc = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": id,
        "type": "OrderedCollection",
        "totalItems": 0,
        "orderedItems": []
    });
    let mut res = Response::json(&oc);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/activity+json"),
    );
    Ok(res)
}
