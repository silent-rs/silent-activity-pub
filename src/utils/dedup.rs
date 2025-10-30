use crate::config::AppConfig;
use lru::LruCache;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;

const DEDUP_TTL: Duration = Duration::from_secs(600); // 10分钟
const DEDUP_CAP: usize = 10_000;

static DEDUP: Lazy<Mutex<LruCache<String, Instant>>> = Lazy::new(|| {
    let cap = NonZeroUsize::new(DEDUP_CAP).unwrap();
    Mutex::new(LruCache::new(cap))
});

// Sled 单例（包含已打开的路径）
static SLED_DB: Lazy<Mutex<Option<(String, sled::Db)>>> = Lazy::new(|| Mutex::new(None));

fn purge_expired(cache: &mut LruCache<String, Instant>) {
    let now = Instant::now();
    let keys: Vec<String> = cache
        .iter()
        .filter_map(|(k, v)| {
            if now.duration_since(*v) > DEDUP_TTL {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    for k in keys {
        let _ = cache.pop(&k);
    }
}

/// 返回 true 表示首次出现，false 表示重复
pub fn record_seen(key: &str) -> bool {
    let mut cache = DEDUP.lock();
    purge_expired(&mut cache);
    if cache.contains(key) {
        false
    } else {
        cache.put(key.to_string(), Instant::now());
        true
    }
}

pub fn record_seen_with_config(key: &str, cfg: &AppConfig) -> bool {
    if cfg.dedup_backend.eq_ignore_ascii_case("sled") {
        // 打开/复用 sled
        let mut guard = SLED_DB.lock();
        let need_open = !matches!(&*guard, Some((path, _)) if path == &cfg.sled_path);
        if need_open {
            match sled::open(&cfg.sled_path) {
                Ok(db) => {
                    *guard = Some((cfg.sled_path.clone(), db));
                }
                Err(e) => {
                    warn!(target="dedup", error=%format!("{e:#}"), "open sled failed, fallback to memory");
                    return record_seen(key);
                }
            }
        }
        // 安全使用 db
        if let Some((_, db)) = &*guard {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs();
            let key_bytes = key.as_bytes();
            if let Ok(Some(ts_bytes)) = db.get(key_bytes) {
                if ts_bytes.len() == 8 {
                    let secs = u64::from_le_bytes(ts_bytes[0..8].try_into().unwrap());
                    if now_secs.saturating_sub(secs) <= DEDUP_TTL.as_secs() {
                        return false; // 未过期，重复
                    }
                }
            }
            let buf = now_secs.to_le_bytes();
            let _ = db.insert(key_bytes, &buf);
            // 后台刷新（丢弃 Future），不中断请求
            // 显式丢弃 Future，避免 clippy 报警
            std::mem::drop(db.flush_async());
            return true;
        }
        // 无法获取 db，回退内存
        return record_seen(key);
    }
    record_seen(key)
}

/// 可扩展的去重后端 trait（为后续 Redis 等实现预留）
#[allow(dead_code)]
pub trait DedupStore: Send + Sync {
    fn record_seen(&self, key: &str, cfg: &AppConfig) -> bool;
}

/// 内存后端适配器
#[allow(dead_code)]
pub struct MemoryStore;
impl DedupStore for MemoryStore {
    fn record_seen(&self, key: &str, _cfg: &AppConfig) -> bool {
        record_seen(key)
    }
}

/// sled 后端适配器
#[allow(dead_code)]
pub struct SledStore;
impl DedupStore for SledStore {
    fn record_seen(&self, key: &str, cfg: &AppConfig) -> bool {
        record_seen_with_config(key, cfg)
    }
}

/// Redis 后端占位（后续可用 feature="redis" 接入）
#[allow(dead_code)]
pub struct RedisStore;
#[allow(dead_code)]
impl DedupStore for RedisStore {
    fn record_seen(&self, key: &str, _cfg: &AppConfig) -> bool {
        // 预留实现：使用 SETNX + EXPIRE 或 Lua 实现 TTL+原子去重
        // 目前占位，回退使用内存逻辑
        record_seen(key)
    }
}
