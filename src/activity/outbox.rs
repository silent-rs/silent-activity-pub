use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use silent::{header, Request, Response, Result, StatusCode};

use crate::config::AppConfig;
// 出站投递由内存队列驱动
use crate::federation::queue::{enqueue, DeliveryJob};

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

#[derive(Debug, Deserialize, Serialize)]
struct OutboxPostBody {
    /// 目标远端 inbox URL
    inbox: String,
    /// 活动内容（原样透传）
    activity: Value,
}

/// POST /users/<name>/outbox 将活动投递到远端 inbox（占位：仅签名并记录日志）
#[silent_openapi::endpoint(
    summary = "投递 Activity 到远端 inbox",
    description = "读取 {inbox, activity} 并使用签名器生成请求头（占位实现：仅日志）"
)]
pub async fn outbox_post(mut req: Request) -> Result<Response> {
    // 解析 body
    let body: OutboxPostBody = match req.json_parse().await {
        Ok(b) => b,
        Err(e) => {
            let mut res = Response::json(&json!({"error": format!("invalid body: {e}")}));
            res.set_status(StatusCode::BAD_REQUEST);
            return Ok(res);
        }
    };

    // 构造投递器
    let cfg: &AppConfig = req.get_config_uncheck();
    let activity_str = body.activity.to_string();
    // 优先入队，由后台 worker 进行重试与实际投递（或日志投递）
    let _ = cfg; // 占位以避免未使用警告（未来可能用于多租户逻辑）
    let ok = enqueue(DeliveryJob {
        inbox_url: body.inbox.clone(),
        body: activity_str,
    });
    if !ok {
        let mut res = Response::json(&json!({"error":"queue_full"}));
        res.set_status(StatusCode::SERVICE_UNAVAILABLE);
        return Ok(res);
    }

    let mut res = Response::json(&json!({"status":"queued"}));
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    Ok(res)
}
