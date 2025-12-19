use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use dashmap::DashMap;
use serde::{Serialize, Serializer};

#[derive(Serialize, Default, Debug)]
pub struct UserTraffic {
    #[serde(serialize_with = "serialize_atomic")] // 应用自定义序列化
    pub upload: AtomicU64,

    #[serde(serialize_with = "serialize_atomic")]
    pub download: AtomicU64,
}
#[derive(Serialize)]
pub struct ServerStatistic(DashMap<String, UserTraffic>);

fn serialize_atomic<S>(x: &AtomicU64, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u64(x.load(Ordering::Relaxed))
}

impl Deref for ServerStatistic {
    type Target = DashMap<String, UserTraffic>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ServerStatistic {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(DashMap::new()))
    }

    pub fn update_upload(&self, user: String, value: usize) {
        let entry = self.0.entry(user);
        entry
            .or_default()
            .upload
            .fetch_add(value as u64, Ordering::Relaxed);
    }

    pub fn update_download(&self, user: String, value: usize) {
        let entry = self.0.entry(user);
        entry
            .or_default()
            .download
            .fetch_add(value as u64, Ordering::Relaxed);
    }
}