use regex::{Regex, RegexSet};

pub struct Redactor {
    detect_set: RegexSet,
    replace_rules: Vec<(Regex, String)>,
    base64_candidate: Regex,
}

impl Redactor {
    pub fn new() -> Self {
        Self::with_path_prefixes(
            ["HOME", "TMPDIR", "TEMP", "TMP"]
                .into_iter()
                .filter_map(|name| std::env::var_os(name))
                .filter_map(|value| value.into_string().ok()),
        )
    }

    fn with_path_prefixes<I>(path_prefixes: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let mut rules = vec![
            (
                Regex::new(r#"(?im)(^|[^A-Za-z0-9_]|\\[rn])(password|secret(?:_key)?|token|api[_-]?key)(\s*:\s*)[|>][-+]?[ \t]*(?:\r?\n[ \t]+[^\r\n]*)+"#).unwrap(),
                "${1}${2}${3}[REDACTED_SECRET]".to_string()
            ),
            (
                Regex::new(r#"(?i)(^|[^A-Za-z0-9_]|\\[rn])(password|secret(?:_key)?|token|api[_-]?key)(\s*:\s*)[|>][-+]?[ \t]*(?:\\[rn][ \t]+[^\\\r\n]*)+"#).unwrap(),
                "${1}${2}${3}[REDACTED_SECRET]".to_string()
            ),
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

        for path_prefix in path_prefixes
            .into_iter()
            .filter(|value| !value.is_empty() && value != "/")
        {
            rules.push((
                Regex::new(&regex::escape(&path_prefix)).unwrap(),
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
            base64_candidate: Regex::new(r"[A-Za-z0-9+/]{12,}={0,2}").unwrap(),
        }
    }

    pub fn has_secret(&self, content: &str) -> bool {
        self.detect_set.is_match(content) || self.has_encoded_secret(content)
    }

    pub fn redact(&self, content: &str) -> String {
        let mut result = content.to_string();
        for (re, replacement) in &self.replace_rules {
            result = re.replace_all(&result, replacement).to_string();
        }
        result = self.redact_encoded_secrets(&result);
        result
    }

    fn has_encoded_secret(&self, content: &str) -> bool {
        self.base64_candidate.find_iter(content).any(|candidate| {
            decode_base64(candidate.as_str())
                .and_then(|decoded| String::from_utf8(decoded).ok())
                .is_some_and(|decoded| self.decoded_text_has_secret(&decoded))
        })
    }

    fn redact_encoded_secrets(&self, content: &str) -> String {
        self.base64_candidate
            .replace_all(content, |captures: &regex::Captures| {
                let candidate = captures.get(0).unwrap().as_str();
                let has_secret = decode_base64(candidate)
                    .and_then(|decoded| String::from_utf8(decoded).ok())
                    .is_some_and(|decoded| self.decoded_text_has_secret(&decoded));

                if has_secret {
                    "[REDACTED_SECRET]".to_string()
                } else {
                    candidate.to_string()
                }
            })
            .to_string()
    }

    fn decoded_text_has_secret(&self, decoded: &str) -> bool {
        if self.detect_set.is_match(decoded) {
            return true;
        }

        let lower = decoded.to_ascii_lowercase();
        lower.contains("secret") && (lower.contains("pass") || lower.contains("token"))
    }

    pub fn count_redactions(before: &str, after: &str) -> usize {
        let count_markers =
            |s: &str| s.matches("[REDACTED_SECRET]").count() + s.matches("[REDACTED_PATH]").count();
        let before_redacts = count_markers(before);
        let after_redacts = count_markers(after);
        after_redacts.saturating_sub(before_redacts)
    }
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    if input.len() % 4 != 0 {
        return None;
    }

    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    let bytes = input.as_bytes();
    for chunk in bytes.chunks_exact(4) {
        let mut values = [0u8; 4];
        let mut padding = 0;

        for (index, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                padding += 1;
                values[index] = 0;
            } else if padding > 0 {
                return None;
            } else {
                values[index] = base64_value(*byte)?;
            }
        }

        output.push((values[0] << 2) | (values[1] >> 4));
        if padding < 2 {
            output.push((values[1] << 4) | (values[2] >> 2));
        }
        if padding == 0 {
            output.push((values[2] << 6) | values[3]);
        }
    }

    Some(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
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
    fn test_redactor_detects_and_redacts_base64_encoded_secret() {
        let redactor = Redactor::new();
        let encoded_secret = "c3VwZXJfc2VjcmV0X3Bhc3M=";

        assert!(redactor.has_secret(encoded_secret));

        let output = redactor.redact(&format!("encoded={encoded_secret}"));
        assert_eq!(output, "encoded=[REDACTED_SECRET]");
        assert!(!output.contains(encoded_secret));
        assert!(!output.contains("super_secret_pass"));
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
    fn test_redactor_detects_and_redacts_multiline_secret_block() {
        let redactor = Redactor::new();
        let input =
            "config:\n  api_key: |\n    line_one_secret\n    line_two_secret\nnext: value\n";

        assert!(redactor.has_secret(input));

        let output = redactor.redact(input);
        assert!(output.contains("api_key: [REDACTED_SECRET]"));
        assert!(output.contains("next: value"));
        assert!(!output.contains("line_one_secret"));
        assert!(!output.contains("line_two_secret"));

        let escaped =
            r#"printf 'config:\n  api_key: |\n    run_line_one_secret\n    run_line_two_secret\n'"#;
        let escaped_output = redactor.redact(escaped);
        assert!(escaped_output.contains("api_key: [REDACTED_SECRET]"));
        assert!(!escaped_output.contains("run_line_one_secret"));
        assert!(!escaped_output.contains("run_line_two_secret"));
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
            Redactor::count_redactions(
                "already [REDACTED_SECRET] and [REDACTED_PATH]",
                "already [REDACTED_SECRET] and [REDACTED_PATH]"
            ),
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
        let redactor = Redactor::with_path_prefixes([home.to_string()]);
        let input = format!("{home}/workspace/project/src/main.rs:1:fn main() {{}}");
        let output = redactor.redact(&input);

        assert!(output.contains("[REDACTED_PATH]/workspace/project"));
        assert!(!output.contains(&home));
    }

    #[test]
    fn test_redactor_redacts_configured_temp_directory() {
        let temp = "/var/folders/sr/gyjtnpgs6lb8wc87qsm0jzp00000gn/T/llm-veil-contract";
        let redactor = Redactor::with_path_prefixes([temp.to_string()]);
        let input = format!("{temp}/fixtures/grep/auth.ts:1:plain text");
        let output = redactor.redact(&input);

        assert!(output.contains("[REDACTED_PATH]/fixtures/grep/auth.ts"));
        assert!(!output.contains(temp));
    }
}
