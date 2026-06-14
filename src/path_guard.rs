use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathAction {
    Block,
    Redact,
    Allow,
}

pub struct PathGuard {
    patterns: Vec<(String, Pattern)>,
    action: PathAction,
}

impl PathGuard {
    pub fn new(blocked_patterns: Vec<String>, action: PathAction) -> Result<Self, glob::PatternError> {
        let mut patterns = Vec::with_capacity(blocked_patterns.len());
        for pat in blocked_patterns {
            let pattern = Pattern::new(&pat)?;
            patterns.push((pat, pattern));
        }

        Ok(Self { patterns, action })
    }

    fn matching_rule(&self, path: &str) -> Option<&str> {
        let path_obj = Path::new(path);

        // 1. パス全体に対する glob マッチ
        if let Some((rule, _)) = self.patterns.iter().find(|(_, pat)| pat.matches(path)) {
            return Some(rule);
        }

        // 先頭の "./" を取り除いた相対パスでチェック
        let normalized = if path.starts_with("./") {
            &path[2..]
        } else {
            path
        };
        if let Some((rule, _)) = self
            .patterns
            .iter()
            .find(|(_, pat)| pat.matches(normalized))
        {
            return Some(rule);
        }

        // 2. ファイル名に対するマッチ (例: "id_rsa.key" が "*.key" にマッチ)
        if let Some(file_name) = path_obj.file_name().and_then(|f| f.to_str()) {
            if let Some((rule, _)) = self.patterns.iter().find(|(_, pat)| pat.matches(file_name)) {
                return Some(rule);
            }
        }

        // 3. 各パスコンポーネント（中間ディレクトリ）に対するマッチ (例: ".git/config" の ".git")
        for comp in path_obj.components() {
            if let Some(comp_str) = comp.as_os_str().to_str() {
                if let Some((rule, _)) = self.patterns.iter().find(|(_, pat)| {
                    pat.matches(comp_str) || pat.matches(&format!("{}/", comp_str))
                }) {
                    return Some(rule);
                }
            }
        }

        None
    }

    pub fn should_block(&self, path: &str) -> bool {
        self.block_rule(path).is_some()
    }

    pub fn block_rule(&self, path: &str) -> Option<&str> {
        if self.action == PathAction::Block {
            self.matching_rule(path)
        } else {
            None
        }
    }

    pub fn should_redact(&self, path: &str) -> bool {
        if self.action == PathAction::Redact {
            self.matching_rule(path).is_some()
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
        ).unwrap();

        // Blockアクションの場合、危険パスはブロックされるべき
        assert!(guard.should_block(".env"));
        assert!(guard.should_block("./.env"));
        assert!(guard.should_block("src/.env"));
        assert!(guard.should_block("config.key"));
        assert!(guard.should_block("./config.key"));
        assert_eq!(guard.block_rule("./config.key"), Some("*.key"));

        // 危険パスでないものはブロックされない
        assert!(!guard.should_block("main.rs"));
    }

    #[test]
    fn test_path_guard_redact() {
        let guard = PathGuard::new(
            vec![".env".to_string(), "*.key".to_string()],
            PathAction::Redact,
        ).unwrap();

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
        ).unwrap();

        // Allowアクションの場合、何もしない
        assert!(!guard.should_block(".env"));
        assert!(!guard.should_redact(".env"));
    }

    #[test]
    fn test_path_guard_invalid_pattern() {
        // 無効なパターン（例: 開き角括弧 "[" のみ）を渡した場合、Err を返すことを期待する
        let res = PathGuard::new(vec!["[".to_string()], PathAction::Block);
        assert!(res.is_err(), "Expected error for invalid pattern '[', but got Ok");
    }
}
