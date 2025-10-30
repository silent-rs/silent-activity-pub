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

/// host-meta: /.well-known/host-meta 提供 WebFinger 入口
#[silent_openapi::endpoint(
    summary = "Host-Meta",
    description = "返回 WebFinger 的 LRDD 链接(XML)"
)]
pub async fn host_meta(_req: Request) -> Result<Response> {
    // 简化：固定指向 /.well-known/webfinger
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <Link rel="lrdd" type="application/xrd+xml" template="{uri}/.well-known/webfinger?resource={uri}"/>
</XRD>"#;
    let mut res = Response::html(xml);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/xrd+xml; charset=utf-8"),
    );
    Ok(res)
}

/// NodeInfo well-known: /.well-known/nodeinfo 返回 nodeinfo 链接
#[silent_openapi::endpoint(
    summary = "NodeInfo well-known",
    description = "返回 NodeInfo 链接列表"
)]
pub async fn nodeinfo_wellknown(req: Request) -> Result<Response> {
    let cfg: &crate::config::AppConfig = req.get_config_uncheck();
    let href = format!("{}/nodeinfo/2.1", cfg.base_url);
    let body = json!({
        "links": [
            {"rel": "http://nodeinfo.diaspora.software/ns/schema/2.1", "href": href}
        ]
    });
    let mut res = Response::json(&body);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    Ok(res)
}

/// NodeInfo 2.1：/nodeinfo/2.1 返回节点信息（占位数据）
#[silent_openapi::endpoint(
    summary = "NodeInfo 2.1",
    description = "返回软件、协议与使用信息(占位)"
)]
pub async fn nodeinfo_21(_req: Request) -> Result<Response> {
    let body = json!({
        "version": "2.1",
        "software": { "name": "silent-activity-pub", "version": env!("CARGO_PKG_VERSION") },
        "protocols": ["activitypub"],
        "services": { "inbound": [], "outbound": [] },
        "openRegistrations": false,
        "usage": { "users": {"total": 0}, "localPosts": 0 }
    });
    let mut res = Response::json(&body);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    Ok(res)
}
