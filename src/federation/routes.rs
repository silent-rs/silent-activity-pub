use chrono::Local;
use silent::prelude::*;
use silent::{Configs, Request, Response, Result};

use crate::activity::{inbox::inbox, models::actor, outbox::outbox};
use crate::config::AppConfig;
use crate::federation::discovery::webfinger;

#[silent_openapi::endpoint(summary = "健康检查", description = "返回服务状态与本地时间")]
async fn health(_req: Request) -> Result<Response> {
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
        .append(Route::new(".well-known").append(Route::new("webfinger").get(webfinger)))
        .append(
            Route::new("users").append(
                Route::new("<name:str>")
                    .get(actor)
                    .append(Route::new("outbox").get(outbox))
                    .append(Route::new("inbox").post(inbox)),
            ),
        )
        .append(Route::new("inbox").post(inbox))
}
