use silent::{Request, Response, Result, StatusCode};

/// Shared inbox 和用户 inbox 占位：返回 202
#[silent_openapi::endpoint(
    summary = "inbox 接收占位",
    description = "接受 Activity（未做签名），返回 202"
)]
pub async fn inbox(_req: Request) -> Result<Response> {
    let mut res = Response::empty();
    res.set_status(StatusCode::ACCEPTED);
    Ok(res)
}
