use serde::Serialize;
use silent::{Response, StatusCode};

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    error_description: &'a str,
}

pub fn json_error(status: StatusCode, code: &'static str, description: &str) -> Response {
    let body = ErrorBody {
        error: code,
        error_description: description,
    };
    let mut res = Response::json(&body);
    res.set_status(status);
    res
}

pub fn unauthorized_with_authenticate(code: &'static str, description: &str) -> Response {
    let mut res = json_error(StatusCode::UNAUTHORIZED, code, description);
    // 非标准化 Scheme，但对 HTTP Signatures 采用 "Signature" 作为表示
    let header_val = format!(
        "Signature realm=\"activitypub\", error=\"{}\", error_description=\"{}\"",
        code, description
    );
    res.headers_mut().insert(
        silent::header::WWW_AUTHENTICATE,
        silent::header::HeaderValue::from_str(&header_val)
            .unwrap_or_else(|_| silent::header::HeaderValue::from_static("Signature")),
    );
    res
}
