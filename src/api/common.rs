use dashmap::DashMap;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Serialize, Default, Debug)]
pub struct UserTraffic {
    #[serde(serialize_with = "serialize_atomic")] // 应用自定义序列化
    pub upload: AtomicU64,

    #[serde(serialize_with = "serialize_atomic")]
    pub download: AtomicU64,
}
pub struct ServerStatistic(DashMap<[u8; 4], UserTraffic>);

// 手动实现序列化，确保 API 输出依然是 Hex 字符串，方便前端阅读
impl Serialize for ServerStatistic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for entry in self.0.iter() {
            // 只在有人看 API 时才进行一次性 Hex 转换
            let hex_key = hex::encode(entry.key());
            map.serialize_entry(&hex_key, entry.value())?;
        }
        map.end()
    }
}

fn serialize_atomic<S>(x: &AtomicU64, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u64(x.load(Ordering::Relaxed))
}

impl Deref for ServerStatistic {
    type Target = DashMap<[u8; 4], UserTraffic>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ServerStatistic {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(DashMap::new()))
    }

    pub fn update_upload(&self, key_id: [u8; 4], value: usize) {
        let entry = self.0.entry(key_id);
        entry
            .or_default()
            .upload
            .fetch_add(value as u64, Ordering::Relaxed);
    }

    pub fn update_download(&self, key_id: [u8; 4], value: usize) {
        let entry = self.0.entry(key_id);
        entry
            .or_default()
            .download
            .fetch_add(value as u64, Ordering::Relaxed);
    }
}
