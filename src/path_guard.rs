use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

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
    pub fn new(
        blocked_patterns: Vec<String>,
        action: PathAction,
    ) -> Result<Self, glob::PatternError> {
        let mut patterns = Vec::with_capacity(blocked_patterns.len());
        for pat in blocked_patterns {
            let pattern = Pattern::new(&pat)?;
            patterns.push((pat, pattern));
        }

        Ok(Self { patterns, action })
    }

    fn matching_rule_for_text(&self, path: &str) -> Option<&str> {
        let slash_normalized;
        let path_for_matching = if path.contains('\\') {
            slash_normalized = path.replace('\\', "/");
            slash_normalized.as_str()
        } else {
            path
        };
        let path_obj = Path::new(path_for_matching);

        // 1. パス全体に対する glob マッチ
        if let Some((rule, _)) = self
            .patterns
            .iter()
            .find(|(_, pat)| pat.matches(path_for_matching))
        {
            return Some(rule);
        }

        // 先頭の "./" を取り除いた相対パスでチェック
        let normalized = if path_for_matching.starts_with("./") {
            &path_for_matching[2..]
        } else {
            path_for_matching
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

    fn matching_rule(&self, path: &str) -> Option<&str> {
        if let Some(rule) = self.matching_rule_for_text(path) {
            return Some(rule);
        }

        fs::canonicalize(path).ok().and_then(|canonical| {
            canonical
                .to_str()
                .and_then(|canonical_path| self.matching_rule_for_text(canonical_path))
        })
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
            vec![".env".to_string(), "*.key".to_string(), ".ssh/".to_string()],
            PathAction::Block,
        )
        .unwrap();

        // Blockアクションの場合、危険パスはブロックされるべき
        assert!(guard.should_block(".env"));
        assert!(guard.should_block("./.env"));
        assert!(guard.should_block("src/.env"));
        assert!(guard.should_block("config.key"));
        assert!(guard.should_block("./config.key"));
        assert_eq!(guard.block_rule("./config.key"), Some("*.key"));
        assert_eq!(guard.block_rule(r"src\.ssh\id_rsa"), Some(".ssh/"));

        // 危険パスでないものはブロックされない
        assert!(!guard.should_block("main.rs"));
    }

    #[test]
    fn test_path_guard_redact() {
        let guard = PathGuard::new(
            vec![".env".to_string(), "*.key".to_string()],
            PathAction::Redact,
        )
        .unwrap();

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
        )
        .unwrap();

        // Allowアクションの場合、何もしない
        assert!(!guard.should_block(".env"));
        assert!(!guard.should_redact(".env"));
    }

    #[test]
    fn test_path_guard_invalid_pattern() {
        // 無効なパターン（例: 開き角括弧 "[" のみ）を渡した場合、Err を返すことを期待する
        let res = PathGuard::new(vec!["[".to_string()], PathAction::Block);
        assert!(
            res.is_err(),
            "Expected error for invalid pattern '[', but got Ok"
        );
    }

    #[test]
    fn test_path_guard_block_canonical_symlink_target() {
        use std::fs::{self, File};
        use std::os::unix::fs::symlink;
        use uuid::Uuid;

        let temp_dir =
            std::env::temp_dir().join(format!("llm-veil-symlink-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let target_path = temp_dir.join("id_rsa");
        File::create(&target_path).unwrap();

        let link_path = temp_dir.join("link_id_rsa");
        #[cfg(unix)]
        {
            if symlink(&target_path, &link_path).is_ok() {
                let guard = PathGuard::new(vec!["id_rsa".to_string()], PathAction::Block).unwrap();

                // シンボリックリンクの指し示す先がブロック対象であれば、リンク自身もブロックされるべき
                assert!(guard.should_block(link_path.to_str().unwrap()));
            }
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_path_guard_block_path_traversal() {
        let guard = PathGuard::new(vec![".env".to_string()], PathAction::Block).unwrap();

        // パストラバーサル経路であってもブロックされるべき
        assert!(guard.should_block("foo/../.env"));
        assert!(guard.should_block("./foo/../.env"));
    }

    #[test]
    fn test_path_guard_block_windows_separator() {
        let guard = PathGuard::new(vec![".ssh/".to_string()], PathAction::Block).unwrap();

        // Windowsのバックスラッシュ区切りであってもブロックされるべき
        assert!(guard.should_block(r"fixtures\.ssh\id_rsa"));
    }

    #[cfg(unix)]
    #[test]
    fn test_path_guard_block_canonical_symlink_target_old() -> std::io::Result<()> {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("llm-veil-path-guard-{}", std::process::id()));
        let ssh_dir = root.join(".ssh");
        std::fs::create_dir_all(&ssh_dir)?;
        let secret_file = ssh_dir.join("id_rsa");
        std::fs::write(&secret_file, "secret")?;
        let public_link = root.join("public_key");
        let _ = std::fs::remove_file(&public_link);
        symlink(&secret_file, &public_link)?;

        let guard = PathGuard::new(vec![".ssh/".to_string()], PathAction::Block).unwrap();
        assert_eq!(
            guard.block_rule(public_link.to_str().unwrap()),
            Some(".ssh/")
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
