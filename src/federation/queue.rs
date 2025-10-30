use crate::config::AppConfig;
use crate::federation::delivery::{build_delivery_from_config, deliver_activity, OutboundDelivery};
use crate::observability::metrics::{record_delivery, record_queue, REGISTRY};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use prometheus::{Gauge, IntCounter};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

#[derive(Clone, Debug)]
pub struct DeliveryJob {
    pub inbox_url: String,
    pub body: String,
}

static QUEUE_SENDER: Lazy<Mutex<Option<mpsc::Sender<DeliveryJob>>>> =
    Lazy::new(|| Mutex::new(None));

static QUEUE_DEPTH: Lazy<Gauge> = Lazy::new(|| {
    let g = Gauge::new("delivery_queue_depth", "current delivery queue depth").unwrap();
    REGISTRY.register(Box::new(g.clone())).ok();
    g
});

static QUEUE_ENQUEUED: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("delivery_queue_enqueued_total", "enqueued jobs").unwrap();
    REGISTRY.register(Box::new(c.clone())).ok();
    c
});

static QUEUE_DROPPED: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("delivery_queue_dropped_total", "dropped jobs when full").unwrap();
    REGISTRY.register(Box::new(c.clone())).ok();
    c
});

pub fn init(cfg: AppConfig) {
    // 如果已经初始化，直接返回
    if QUEUE_SENDER.lock().is_some() {
        return;
    }
    let backend = cfg.queue_backend.to_ascii_lowercase();
    if backend == "sled" {
        init_sled(cfg);
        return;
    }
    let cap: usize = cfg.queue_cap;
    let workers: usize = cfg.queue_workers.clamp(1, 16);
    let (tx, rx) = mpsc::channel::<DeliveryJob>(cap);
    *QUEUE_SENDER.lock() = Some(tx);
    QUEUE_DEPTH.set(0.0);
    spawn_workers(cfg, rx, workers);
}

fn spawn_workers(cfg: AppConfig, rx: mpsc::Receiver<DeliveryJob>, workers: usize) {
    // 克隆配置给每个工作线程
    let shared = Arc::new(AsyncMutex::new(rx));
    for _ in 0..workers {
        let cfg_clone = cfg.clone();
        let shared_rx = shared.clone();
        tokio::spawn(async move {
            // 预创建占位 signer 以减少重复开销（仅用于日志通道）
            let logging = build_delivery_from_config(&cfg_clone);
            loop {
                let job_opt = {
                    let mut guard = shared_rx.lock().await;
                    guard.recv().await
                };
                let Some(job) = job_opt else { break };
                QUEUE_DEPTH.dec();
                // 根据开关选择真实投递或日志投递
                let http_enabled = cfg_clone.delivery_http;
                let result = if http_enabled {
                    deliver_activity(&cfg_clone, &job.inbox_url, &job.body).await
                } else {
                    logging.post_activity(&job.inbox_url, &job.body).await
                };
                if result.is_err() {
                    // 失败计数，使用现有 delivery 指标
                    let scheme = if job.inbox_url.starts_with("https://") {
                        "https"
                    } else {
                        "http"
                    };
                    record_delivery(scheme, false, 0, 0);
                }
            }
        });
    }
}

pub fn enqueue(job: DeliveryJob) -> bool {
    if let Some(tx) = QUEUE_SENDER.lock().as_ref() {
        if tx.try_send(job).is_ok() {
            record_queue("memory", "enqueued");
            QUEUE_ENQUEUED.inc();
            QUEUE_DEPTH.inc();
            return true;
        } else {
            record_queue("memory", "dropped");
            QUEUE_DROPPED.inc();
            return false;
        }
    }
    // sled backend: 落盘
    if std::env::var("AP_QUEUE_BACKEND")
        .unwrap_or_else(|_| "memory".into())
        .eq_ignore_ascii_case("sled")
    {
        return enqueue_sled(job);
    }
    false
}

// ========== sled backend ==========

static SLED_DB: Lazy<Mutex<Option<sled::Db>>> = Lazy::new(|| Mutex::new(None));

fn init_sled(cfg: AppConfig) {
    let path = cfg.sled_path.clone();
    match sled::open(&path) {
        Ok(db) => {
            *SLED_DB.lock() = Some(db);
            spawn_sled_worker(cfg);
        }
        Err(e) => {
            tracing::warn!(target="queue", error=%format!("{e:#}"), "open sled for queue failed, fallback to memory");
            // 回退到内存队列
            let cap: usize = std::env::var("AP_QUEUE_CAP")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(1000);
            let workers: usize = std::env::var("AP_QUEUE_WORKERS")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(2)
                .clamp(1, 16);
            let (tx, rx) = mpsc::channel::<DeliveryJob>(cap);
            *QUEUE_SENDER.lock() = Some(tx);
            QUEUE_DEPTH.set(0.0);
            spawn_workers(cfg, rx, workers);
        }
    }
}

fn enqueue_sled(job: DeliveryJob) -> bool {
    let db_opt = SLED_DB.lock();
    if let Some(db) = &*db_opt {
        let tree = db.open_tree("ap_queue").ok();
        if let Some(tree) = tree {
            // tail 计数自增
            let tail_key = b"q:tail";
            let head_key = b"q:head";
            let tail = tree
                .get(tail_key)
                .ok()
                .flatten()
                .map(|v| u64::from_le_bytes(v.as_ref().try_into().unwrap()))
                .unwrap_or(0);
            let next = tail.saturating_add(1);
            let k = format!("q:item:{:020}", next);
            let payload = format!("{}\n{}", job.inbox_url, job.body);
            if tree.insert(k.as_bytes(), payload.as_bytes()).is_ok() {
                let _ = tree.insert(tail_key, &next.to_le_bytes());
                let zero = 0u64.to_le_bytes();
                let _ =
                    tree.compare_and_swap(head_key, None as Option<&[u8]>, Some(zero.as_slice()));
                std::mem::drop(tree.flush_async());
                record_queue("sled", "enqueued");
                return true;
            }
        }
    }
    false
}

fn spawn_sled_worker(cfg: AppConfig) {
    tokio::spawn(async move {
        let poll_ms: u64 = cfg.queue_poll_ms;
        loop {
            let maybe_job = {
                let db_opt = SLED_DB.lock();
                if let Some(db) = &*db_opt {
                    if let Ok(tree) = db.open_tree("ap_queue") {
                        // 获取 head 与 tail
                        let head = tree
                            .get(b"q:head")
                            .ok()
                            .flatten()
                            .map(|v| u64::from_le_bytes(v.as_ref().try_into().unwrap()))
                            .unwrap_or(0);
                        let tail = tree
                            .get(b"q:tail")
                            .ok()
                            .flatten()
                            .map(|v| u64::from_le_bytes(v.as_ref().try_into().unwrap()))
                            .unwrap_or(0);
                        if head < tail {
                            let next = head + 1;
                            let k = format!("q:item:{:020}", next);
                            if let Ok(Some(val)) = tree.get(k.as_bytes()) {
                                if let Ok(s) = std::str::from_utf8(&val) {
                                    let mut it = s.splitn(2, '\n');
                                    let inbox_url = it.next().unwrap_or("").to_string();
                                    let body = it.next().unwrap_or("").to_string();
                                    Some((next, inbox_url, body))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some((seq, inbox_url, body)) = maybe_job {
                // 执行投递
                let res = deliver_activity(&cfg, &inbox_url, &body).await;
                if res.is_ok() {
                    // 删除并前进 head
                    let db_opt = SLED_DB.lock();
                    if let Some(db) = &*db_opt {
                        if let Ok(tree) = db.open_tree("ap_queue") {
                            let k = format!("q:item:{:020}", seq);
                            let _ = tree.remove(k.as_bytes());
                            let _ = tree.insert(b"q:head", &seq.to_le_bytes());
                            std::mem::drop(tree.flush_async());
                            record_queue("sled", "dequeued");
                        }
                    }
                } else {
                    // 失败：短暂等待，避免紧循环
                    tokio::time::sleep(std::time::Duration::from_millis(poll_ms)).await;
                }
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(poll_ms)).await;
            }
        }
    });
}
