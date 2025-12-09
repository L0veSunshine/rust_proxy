use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, atomic};

pub struct UserTraffic {
    upload: atomic::AtomicU64,
    download: atomic::AtomicU64,
}
pub struct ServerStatistic(HashMap<String, UserTraffic>);

impl Deref for ServerStatistic {
    type Target = HashMap<String, UserTraffic>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ServerStatistic {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(HashMap::new()))
    }

    pub fn update_upload(&self, user: String, value: usize) {
        if let Some(u) = self.get(&user) {
            u.upload.store(value as u64, atomic::Ordering::Relaxed);
        }
    }

    pub fn update_download(&self, user: String, value: usize) {
        if let Some(u) = self.get(&user) {
            u.download.store(value as u64, atomic::Ordering::Relaxed);
        }
    }
}
