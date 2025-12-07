use crate::secret::totp::derive_key_id;
use std::collections::HashMap;
use std::io::Result;
use std::sync::Arc;

pub fn get_shared_keys(file_name: &str) -> Result<Vec<Vec<u8>>> {
    let content = std::fs::read_to_string(file_name)?;
    let keys: Vec<Vec<u8>> = content
        .split(";")
        .map(|k| k.trim())
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.as_bytes().to_vec())
            }
        })
        .collect();
    Ok(keys)
}

pub fn build_key_map(keys: &[Vec<u8>]) -> Arc<HashMap<[u8; 4], Vec<u8>>> {
    let mut key_map: HashMap<[u8; 4], Vec<u8>> = HashMap::new();
    for key in keys.iter() {
        let id = derive_key_id(key);
        key_map.entry(id).or_insert(key.clone());
    }
    Arc::new(key_map)
}
