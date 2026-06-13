use regex::{Regex, RegexSet};

pub struct Redactor {
    detect_set: RegexSet,
    replace_rules: Vec<(Regex, String)>,
}

impl Redactor {
    pub fn new() -> Self {
        let rules = vec![
            (
                Regex::new(r#"(?i)(password|secret|token|api_key)(\s*[:=]\s*)([^\s'"\r\n]+)"#).unwrap(),
                "${1}${2}[REDACTED_SECRET]".to_string()
            ),
            (
                Regex::new(r#"(?i)(authorization\s*:\s*bearer\s+)([^\s'"\r\n]+)"#).unwrap(),
                "${1}[REDACTED_SECRET]".to_string()
            ),
            (
                // URL接続文字列内のパスワード検知
                Regex::new(r#"(?i)((?:postgres|mysql|mongodb|redis|sqlite|mssql|sftp|http|https)://[^:\s]+:)([^@\s]+)"#).unwrap(),
                "${1}[REDACTED_SECRET]".to_string()
            ),
            (
                Regex::new(r#"(?i)(AKIA[A-Z0-9]{16})"#).unwrap(),
                "[REDACTED_SECRET]".to_string()
            ),
            (
                Regex::new(r#"(?s)-----BEGIN [A-Z0-9_ ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_ ]+PRIVATE KEY-----"#).unwrap(),
                "[REDACTED_SECRET]".to_string()
            ),
            (
                Regex::new(r#"(?i)(-----BEGIN [A-Z0-9_ ]+PRIVATE KEY-----)"#).unwrap(),
                "[REDACTED_SECRET]".to_string()
            ),
        ];

        let detect_patterns = vec![
            r#"(?i)(password|secret|token|api_key)\s*[:=]"#,
            r#"(?i)authorization\s*:\s*bearer"#,
            r#"(?i)(postgres|mysql|mongodb|redis|sqlite|mssql|sftp|http|https)://[^:\s]+:[^@\s]+@"#,
            r#"(?i)AKIA[A-Z0-9]{16}"#,
            r#"-----BEGIN [A-Z0-9_ ]+PRIVATE KEY-----"#,
        ];
        let detect_set = RegexSet::new(detect_patterns).unwrap();

        Self {
            detect_set,
            replace_rules: rules,
        }
    }

    pub fn has_secret(&self, content: &str) -> bool {
        self.detect_set.is_match(content)
    }

    pub fn redact(&self, content: &str) -> String {
        let mut result = content.to_string();
        for (re, replacement) in &self.replace_rules {
            result = re.replace_all(&result, replacement).to_string();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redactor_has_secret() {
        let redactor = Redactor::new();

        // シークレットが含まれる場合は true
        assert!(redactor.has_secret("password=super_secret_123"));
        assert!(redactor.has_secret("api_key: \"AIzaSy...\""));
        assert!(redactor.has_secret("Authorization: Bearer my_jwt_token"));
        assert!(redactor.has_secret("postgres://user:pass@localhost:5432/db"));
        assert!(redactor.has_secret("-----BEGIN RSA PRIVATE KEY-----"));
        
        // 含まれない場合は false
        assert!(!redactor.has_secret("hello world"));
    }

    #[test]
    fn test_redactor_redact() {
        let redactor = Redactor::new();

        let input = "my password=12345 and token=abcde and db=postgres://user:pass@localhost:5432/db";
        let output = redactor.redact(input);
        assert!(output.contains("[REDACTED_SECRET]"));
        assert!(!output.contains("12345"));
        assert!(!output.contains("abcde"));
        assert!(!output.contains("user:pass@"));
    }
}
