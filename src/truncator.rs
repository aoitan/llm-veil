pub fn truncate(content: &str, max_chars: usize) -> String {
    let chars: Vec<char> = content.chars().collect();
    let total_chars = chars.len();

    if total_chars <= max_chars {
        return content.to_string();
    }

    let half = max_chars / 2;
    let prefix_len = half;
    let suffix_len = max_chars - half;

    let prefix: String = chars[0..prefix_len].iter().collect();
    let suffix: String = chars[total_chars - suffix_len..total_chars]
        .iter()
        .collect();

    let omitted: String = chars[prefix_len..total_chars - suffix_len].iter().collect();
    let omitted_bytes = omitted.len();

    format!(
        "{}\n... [TRUNCATED: omitted {} bytes] ...\n{}",
        prefix, omitted_bytes, suffix
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncator_no_truncate() {
        let input = "hello";
        let output = truncate(input, 10);
        assert_eq!(output, "hello");
    }

    #[test]
    fn test_truncator_with_ascii() {
        let input = "abcdefghijkl"; // 12 chars
        let output = truncate(input, 10); // max 10 chars -> keep 5 prefix, 5 suffix

        assert!(output.contains("[TRUNCATED: omitted 2 bytes]"));
        assert!(output.starts_with("abcde"));
        assert!(output.ends_with("hijkl"));
    }

    #[test]
    fn test_truncator_with_multibyte() {
        let input = "あいうえおかきくけこさし"; // 12 chars (each multibyte char is 3 bytes in UTF-8)
        let output = truncate(input, 10); // max 10 chars -> keep 5 prefix, 5 suffix

        assert!(output.contains("[TRUNCATED: omitted 6 bytes]"));
        assert!(output.starts_with("あいうえお"));
        assert!(output.ends_with("くけこさし"));
    }
}
