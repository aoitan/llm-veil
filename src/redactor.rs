use regex::{Regex, RegexSet};

pub struct Redactor {
    detect_set: RegexSet,
    replace_rules: Vec<(Regex, String)>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::with_home_path(
            std::env::var_os("HOME")
                .and_then(|value| value.into_string().ok()),
        )
    }

    fn with_home_path(home: Option<String>) -> Self {
        let mut rules = vec![
            (
                Regex::new(r#"(?i)(^|[^A-Za-z0-9_]|\\[rn])(password|secret(?:_key)?|token|api[_-]?key)(\s*[:=]\s*)(\\?["'])([^'"\r\n]*?)(\\?["'])"#).unwrap(),
                "${1}${2}${3}${4}[REDACTED_SECRET]${6}".to_string()
            ),
            (
                Regex::new(r#"(?i)(^|[^A-Za-z0-9_]|\\[rn])(password|secret(?:_key)?|token|api[_-]?key)(\s*[:=]\s*)([^\s'"\r\n;\\]+)"#).unwrap(),
                "${1}${2}${3}[REDACTED_SECRET]".to_string()
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
            (
                Regex::new(r"/(Users|home)/[a-zA-Z0-9_-]+").unwrap(),
                "[REDACTED_PATH]".to_string()
            ),
            (
                Regex::new(r"(?i)[A-Z]:\\Users\\[a-zA-Z0-9_.-]+").unwrap(),
                "[REDACTED_PATH]".to_string()
            ),
        ];

        if let Some(home) = home.filter(|value| !value.is_empty() && value != "/") {
            rules.push((
                Regex::new(&regex::escape(&home)).unwrap(),
                "[REDACTED_PATH]".to_string(),
            ));
        }

        let detect_patterns = vec![
            r#"(?i)(^|[^A-Za-z0-9_]|\\[rn])(password|secret(?:_key)?|token|api[_-]?key)\s*[:=]"#,
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

    pub fn count_redactions(before: &str, after: &str) -> usize {
        let count_markers = |s: &str| {
            s.matches("[REDACTED_SECRET]").count() + s.matches("[REDACTED_PATH]").count()
        };
        let before_redacts = count_markers(before);
        let after_redacts = count_markers(after);
        after_redacts.saturating_sub(before_redacts)
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
        assert!(redactor.has_secret("SECRET_KEY=12345"));
        assert!(redactor.has_secret("Authorization: Bearer my_jwt_token"));
        assert!(redactor.has_secret("postgres://user:pass@localhost:5432/db"));
        assert!(redactor.has_secret("-----BEGIN RSA PRIVATE KEY-----"));

        // 含まれない場合は false
        assert!(!redactor.has_secret("hello world"));
    }

    #[test]
    fn test_redactor_redact() {
        let redactor = Redactor::new();

        let input =
            "my password=12345 and token=abcde and db=postgres://user:pass@localhost:5432/db";
        let output = redactor.redact(input);
        assert!(output.contains("[REDACTED_SECRET]"));
        assert!(!output.contains("12345"));
        assert!(!output.contains("abcde"));
        assert!(!output.contains("user:pass@"));

        let quoted = redactor.redact("const token = \"my_jwt_token\";");
        assert_eq!(quoted, "const token = \"[REDACTED_SECRET]\";");

        let secret_key = redactor.redact("SECRET_KEY=12345");
        assert_eq!(secret_key, "SECRET_KEY=[REDACTED_SECRET]");

        let escaped_newline = redactor.redact(r#"printf 'Hello\nSECRET_KEY=12345\n'"#);
        assert!(escaped_newline.contains(r#"SECRET_KEY=[REDACTED_SECRET]"#));
        assert!(!escaped_newline.contains("12345"));
    }

    #[test]
    fn test_redactor_redacts_quoted_secret_with_spaces() {
        let redactor = Redactor::new();

        let double_quoted = redactor.redact(r#"password = "my super secret""#);
        assert_eq!(double_quoted, "password = \"[REDACTED_SECRET]\"");
        assert!(!double_quoted.contains("my super secret"));

        let single_quoted = redactor.redact("api_key='value with spaces'");
        assert_eq!(single_quoted, "api_key='[REDACTED_SECRET]'");
        assert!(!single_quoted.contains("value with spaces"));

        let escaped_quoted = redactor.redact(r#"printf "password=\"shell escaped value\"""#);
        assert_eq!(escaped_quoted, r#"printf "password=\"[REDACTED_SECRET]\"""#);
        assert!(!escaped_quoted.contains("shell escaped value"));
    }

    #[test]
    fn test_count_redactions_counts_new_markers_only() {
        assert_eq!(
            Redactor::count_redactions("token=abc", "token=[REDACTED_SECRET]"),
            1
        );
        assert_eq!(
            Redactor::count_redactions("/Users/user", "[REDACTED_PATH]"),
            1
        );
        assert_eq!(
            Redactor::count_redactions("already [REDACTED_SECRET] and [REDACTED_PATH]", "already [REDACTED_SECRET] and [REDACTED_PATH]"),
            0
        );
    }

    #[test]
    fn test_redactor_redacts_absolute_path() {
        let redactor = Redactor::new();
        let input = "/Users/aoitan/workspace/token_filter/tomoe_works/test_data/grep/auth.ts:2:const token = \"my_jwt_token\";";
        let output = redactor.redact(input);
        assert!(output.contains("[REDACTED_PATH]"));
        assert!(!output.contains("aoitan"));
    }

    #[test]
    fn test_redactor_redacts_windows_user_absolute_path() {
        let redactor = Redactor::new();
        let input = r#"C:\Users\aoitan\workspace\file.txt:1:token=abc123"#;
        let output = redactor.redact(input);
        assert!(output.contains(r#"[REDACTED_PATH]\workspace\file.txt"#));
        assert!(!output.contains("aoitan"));
    }

    #[test]
    fn test_redactor_redacts_configured_home_directory() {
        let home = "/mnt/company/alice";
        let redactor = Redactor::with_home_path(Some(home.to_string()));
        let input = format!("{home}/workspace/project/src/main.rs:1:fn main() {{}}");
        let output = redactor.redact(&input);

        assert!(output.contains("[REDACTED_PATH]/workspace/project"));
        assert!(!output.contains(&home));
    }
}
