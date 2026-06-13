use std::fs;
use std::io;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Stats {
    pub run_id: String,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub raw_bytes: usize,
    pub returned_bytes: usize,
    pub reduction: f64,
    pub redactions: usize,
    pub prompt_injection_warnings: usize,
    pub truncated: bool,
    pub timeout: bool,
    pub timestamp: String,
}

fn get_stats_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("llm-veil")
}

pub fn save_stats(stats: &Stats) -> Result<(), io::Error> {
    let dir = get_stats_dir();
    fs::create_dir_all(&dir)?;

    let file_path = dir.join(format!("{}.json", stats.run_id));
    let json = serde_json::to_string_pretty(stats)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&file_path, json)?;

    let last_run_path = dir.join("last_run");
    fs::write(&last_run_path, &stats.run_id)?;

    Ok(())
}

pub fn load_stats(run_id: &str) -> Result<Stats, io::Error> {
    let dir = get_stats_dir();
    let file_path = dir.join(format!("{}.json", run_id));
    
    let json = fs::read_to_string(&file_path)?;
    let stats: Stats = serde_json::from_str(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
    Ok(stats)
}

pub fn load_last_stats() -> Result<Stats, io::Error> {
    let dir = get_stats_dir();
    let last_run_path = dir.join("last_run");
    
    let run_id = fs::read_to_string(&last_run_path)?;
    load_stats(&run_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use chrono::Utc;

    #[test]
    fn test_save_and_load_stats() {
        let run_id = Uuid::new_v4().to_string();
        let stats = Stats {
            run_id: run_id.clone(),
            command: Some("pytest -q".to_string()),
            exit_code: Some(1),
            raw_bytes: 184220,
            returned_bytes: 6230,
            reduction: 96.6,
            redactions: 2,
            prompt_injection_warnings: 1,
            truncated: true,
            timeout: false,
            timestamp: Utc::now().to_rfc3339(),
        };

        // 保存ができること
        assert!(save_stats(&stats).is_ok());

        // 読み込みができること
        let loaded = load_stats(&run_id).unwrap();
        assert_eq!(loaded, stats);

        // 最後に保存した stats も取得できること
        let last_loaded = load_last_stats().unwrap();
        assert_eq!(last_loaded, stats);
    }
}
