use silent::prelude::Route;
use silent::Server;
use silent_openapi::{OpenApiDoc, RouteOpenApiExt, SwaggerUiHandler, SwaggerUiOptions};
use std::env;
use std::net::SocketAddr;

mod activity;
mod auth;
mod config;
mod federation;
mod observability;
mod store;
mod types;
mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    observability::init_tracing();

    // 读取监听地址
    let addr: SocketAddr = env::var("AP_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .expect("invalid AP_LISTEN");

    let cfg = config::AppConfig::load_from_env();
    let routes = federation::routes::build_routes(cfg);

    // 基于业务路由生成 OpenAPI，创建 Swagger UI Handler 并作为路由挂载到 /docs
    let openapi = routes.to_openapi("silent-activity-pub API", env!("CARGO_PKG_VERSION"));
    let openapi = OpenApiDoc::from_openapi(openapi).into_openapi();
    let options = SwaggerUiOptions {
        try_it_out_enabled: true,
    };
    let swagger = SwaggerUiHandler::with_options("/docs", openapi, options)
        .expect("Failed to create Swagger UI");

    let app = Route::new("").append(swagger.into_route()).append(routes);

    Server::new().bind(addr).serve(app).await;
    Ok(())
}
