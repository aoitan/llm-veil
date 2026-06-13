use serde::{Serialize, Deserialize};
use glob::Pattern;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathAction {
    Block,
    Redact,
    Allow,
}

pub struct PathGuard {
    patterns: Vec<Pattern>,
    action: PathAction,
}

impl PathGuard {
    pub fn new(blocked_patterns: Vec<String>, action: PathAction) -> Self {
        let patterns = blocked_patterns
            .into_iter()
            .filter_map(|pat| Pattern::new(&pat).ok())
            .collect();

        Self { patterns, action }
    }

    fn matches_any(&self, path: &str) -> bool {
        let path_obj = Path::new(path);

        // 1. パス全体に対する glob マッチ
        if self.patterns.iter().any(|pat| pat.matches(path)) {
            return true;
        }

        // 先頭の "./" を取り除いた相対パスでチェック
        let normalized = if path.starts_with("./") {
            &path[2..]
        } else {
            path
        };
        if self.patterns.iter().any(|pat| pat.matches(normalized)) {
            return true;
        }

        // 2. ファイル名に対するマッチ (例: "id_rsa.key" が "*.key" にマッチ)
        if let Some(file_name) = path_obj.file_name().and_then(|f| f.to_str()) {
            if self.patterns.iter().any(|pat| pat.matches(file_name)) {
                return true;
            }
        }

        // 3. 各パスコンポーネント（中間ディレクトリ）に対するマッチ (例: ".git/config" の ".git")
        for comp in path_obj.components() {
            if let Some(comp_str) = comp.as_os_str().to_str() {
                if self.patterns.iter().any(|pat| {
                    pat.matches(comp_str) || pat.matches(&format!("{}/", comp_str))
                }) {
                    return true;
                }
            }
        }

        false
    }

    pub fn should_block(&self, path: &str) -> bool {
        if self.action == PathAction::Block {
            self.matches_any(path)
        } else {
            false
        }
    }

    pub fn should_redact(&self, path: &str) -> bool {
        if self.action == PathAction::Redact {
            self.matches_any(path)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_guard_block() {
        let guard = PathGuard::new(
            vec![".env".to_string(), "*.key".to_string()],
            PathAction::Block,
        );

        // Blockアクションの場合、危険パスはブロックされるべき
        assert!(guard.should_block(".env"));
        assert!(guard.should_block("./.env"));
        assert!(guard.should_block("src/.env"));
        assert!(guard.should_block("config.key"));
        assert!(guard.should_block("./config.key"));
        
        // 危険パスでないものはブロックされない
        assert!(!guard.should_block("main.rs"));
    }

    #[test]
    fn test_path_guard_redact() {
        let guard = PathGuard::new(
            vec![".env".to_string(), "*.key".to_string()],
            PathAction::Redact,
        );

        // Redactアクションの場合、ブロックはせず、サニタイズ対象とする
        assert!(!guard.should_block(".env"));
        assert!(guard.should_redact(".env"));
        assert!(guard.should_redact("./.env"));
        assert!(guard.should_redact("src/.env"));
    }

    #[test]
    fn test_path_guard_allow() {
        let guard = PathGuard::new(
            vec![".env".to_string(), "*.key".to_string()],
            PathAction::Allow,
        );

        // Allowアクションの場合、何もしない
        assert!(!guard.should_block(".env"));
        assert!(!guard.should_redact(".env"));
    }
}
