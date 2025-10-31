use chrono::Local;
use silent::prelude::*;
use silent::{Configs, Request, Response, Result};

use crate::activity::{
    inbox::inbox,
    models::actor,
    outbox::{outbox, outbox_post},
};
use crate::config::AppConfig;
use crate::federation::discovery::{host_meta, nodeinfo_21, nodeinfo_wellknown, webfinger};
use crate::observability::metrics::metrics_handler;

#[silent_openapi::endpoint(summary = "健康检查", description = "返回服务状态与本地时间")]
async fn health(req: Request) -> Result<Response> {
    if *req.method() == http::Method::HEAD {
        return Ok(Response::empty());
    }
    let body = serde_json::json!({
        "status": "ok",
        "time": Local::now().naive_local().to_string(),
        "request_id": scru128::new_string()
    });
    Ok(Response::json(&body))
}

pub fn build_routes(cfg: AppConfig) -> Route {
    let mut root = Route::new_root();
    // 注入配置
    root.set_configs(Some({
        let mut c = Configs::default();
        c.insert(cfg);
        c
    }));

    root.append(Route::new("health").get(health))
        .append(Route::new("metrics").get(metrics_handler))
        .append(
            Route::new(".well-known")
                .append(Route::new("webfinger").get(webfinger))
                .append(Route::new("host-meta").get(host_meta))
                .append(Route::new("nodeinfo").get(nodeinfo_wellknown)),
        )
        .append(Route::new("nodeinfo").append(Route::new("2.1").get(nodeinfo_21)))
        .append(
            Route::new("users").append(
                Route::new("<name:str>")
                    .get(actor)
                    .append(Route::new("outbox").get(outbox).post(outbox_post))
                    .append(Route::new("inbox").post(inbox)),
            ),
        )
        .append(Route::new("inbox").post(inbox))
}
