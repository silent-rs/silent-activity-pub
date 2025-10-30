use silent::prelude::Route;
use silent::Server;
use silent_openapi::{OpenApiDoc, RouteOpenApiExt, SwaggerUiHandler, SwaggerUiOptions};
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

    let cfg = config::AppConfig::load();
    // 读取监听地址（来自配置文件/环境）
    let addr: SocketAddr = cfg
        .listen_addr
        .parse()
        .expect("invalid listen addr in config");
    // 初始化出站投递队列（内存）
    federation::queue::init(cfg.clone());
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
