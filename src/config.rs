use std::io::Result;

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
