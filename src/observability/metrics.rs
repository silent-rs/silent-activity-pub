use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use silent::{header, Response};

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

pub static DELIVERY_COUNTER: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("delivery_total", "delivery result counter"),
        &["scheme", "result", "code"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).ok();
    c
});

pub static DELIVERY_HISTOGRAM: Lazy<HistogramVec> = Lazy::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new("delivery_duration_ms", "delivery duration in ms").buckets(vec![
            5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0,
        ]),
        &["scheme"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).ok();
    h
});

pub static INBOUND_COUNTER: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("inbound_total", "inbound inbox counter"),
        &["endpoint", "result"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).ok();
    c
});

pub static DEDUP_COUNTER: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("dedup_total", "dedup hits and misses"),
        &["backend", "result"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).ok();
    c
});

pub fn record_delivery(scheme: &str, ok: bool, code: u16, elapsed_ms: u64) {
    let result = if ok { "ok" } else { "error" };
    DELIVERY_COUNTER
        .with_label_values(&[scheme, result, &code.to_string()])
        .inc();
    DELIVERY_HISTOGRAM
        .with_label_values(&[scheme])
        .observe(elapsed_ms as f64);
}

pub fn record_inbound(endpoint: &str, result: &str) {
    INBOUND_COUNTER.with_label_values(&[endpoint, result]).inc();
}

pub fn record_dedup(backend: &str, result: &str) {
    DEDUP_COUNTER.with_label_values(&[backend, result]).inc();
}

pub async fn metrics_handler(_req: silent::Request) -> silent::Result<Response> {
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    let mut res = Response::empty();
    res.set_header(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    res.set_body(buffer.into());
    Ok(res)
}
