use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::path_guard::PathAction;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub blocked_patterns: Vec<String>,
    pub action: PathAction,
    pub timeout_seconds: u64,
    pub max_chars: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            blocked_patterns: vec![
                ".env".to_string(),
                "*.pem".to_string(),
                "*.key".to_string(),
                "*.p12".to_string(),
                "*.pfx".to_string(),
                ".aws/".to_string(),
                ".ssh/".to_string(),
                ".gnupg/".to_string(),
                ".git/".to_string(),
                "node_modules/".to_string(),
                "dist/".to_string(),
                "build/".to_string(),
            ],
            action: PathAction::Block,
            timeout_seconds: 30,
            max_chars: 12000,
        }
    }
}

fn get_config_path() -> Option<PathBuf> {
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())?;
    Some(PathBuf::from(home).join(".config").join("llm-veil").join("config.json"))
}

pub fn load_config() -> Config {
    let mut config = Config::default();
    if let Some(path) = get_config_path() {
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(parsed) = serde_json::from_str::<Config>(&content) {
                    config = parsed;
                }
            }
        }
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.max_chars, 12000);
        assert_eq!(config.action, PathAction::Block);
        assert!(config.blocked_patterns.contains(&".env".to_string()));
    }
}
