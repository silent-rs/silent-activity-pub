use lru::LruCache;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const DEDUP_TTL: Duration = Duration::from_secs(600); // 10分钟
const DEDUP_CAP: usize = 10_000;

static DEDUP: Lazy<Mutex<LruCache<String, Instant>>> = Lazy::new(|| {
    let cap = NonZeroUsize::new(DEDUP_CAP).unwrap();
    Mutex::new(LruCache::new(cap))
});

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
