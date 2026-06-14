use crate::redactor::Redactor;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;

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
    let json = sanitized_stats_json(stats)?;
    fs::write(&file_path, json)?;

    let last_run_path = dir.join("last_run");
    fs::write(&last_run_path, &stats.run_id)?;

    Ok(())
}

pub fn sanitized_stats_json(stats: &Stats) -> Result<String, io::Error> {
    let redactor = Redactor::new();
    let mut sanitized_stats = stats.clone();
    sanitized_stats.command = stats
        .command
        .as_deref()
        .map(|command| redactor.redact(command));

    let json = serde_json::to_string_pretty(&sanitized_stats)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(redactor.redact(&json))
}

pub fn load_stats(run_id: &str) -> Result<Stats, io::Error> {
    let dir = get_stats_dir();
    let file_path = dir.join(format!("{}.json", run_id));

    let json = fs::read_to_string(&file_path)?;
    let stats: Stats =
        serde_json::from_str(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

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
    use chrono::Utc;
    use uuid::Uuid;

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

    #[test]
    fn test_save_stats_redacts_secret_command_before_json_persistence() {
        let run_id = Uuid::new_v4().to_string();
        let stats = Stats {
            run_id: run_id.clone(),
            command: Some("sh -c 'printf SECRET_KEY=12345'".to_string()),
            exit_code: Some(0),
            raw_bytes: 16,
            returned_bytes: 16,
            reduction: 0.0,
            redactions: 0,
            prompt_injection_warnings: 0,
            truncated: false,
            timeout: false,
            timestamp: Utc::now().to_rfc3339(),
        };

        save_stats(&stats).unwrap();

        let loaded = load_stats(&run_id).unwrap();
        let command = loaded.command.unwrap();
        assert!(command.contains("SECRET_KEY=[REDACTED_SECRET]"));
        assert!(!command.contains("12345"));

        let json_path = get_stats_dir().join(format!("{}.json", run_id));
        let json = fs::read_to_string(&json_path).unwrap();
        assert!(!json.contains("12345"));
    }
}
