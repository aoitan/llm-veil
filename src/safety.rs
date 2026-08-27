use crate::redactor::Redactor;

/// Content that has crossed the storage sanitation boundary.
///
/// The fields stay private so storage can only consume content produced by
/// the constructors in this module. The type itself is crate-visible because
/// the persistence facade is the boundary between application code and the
/// storage implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SanitizedStoredContent {
    stdout: String,
    stderr: String,
}

impl SanitizedStoredContent {
    /// Return sanitized stdout without exposing mutable storage content.
    pub(crate) fn stdout(&self) -> &str {
        &self.stdout
    }

    /// Return sanitized stderr without exposing mutable storage content.
    pub(crate) fn stderr(&self) -> &str {
        &self.stderr
    }
}

pub(crate) fn sanitize_for_storage(
    stdout: &str,
    stderr: &str,
    redactor: &Redactor,
) -> SanitizedStoredContent {
    SanitizedStoredContent {
        stdout: sanitize_text(stdout, redactor),
        stderr: sanitize_text(stderr, redactor),
    }
}

pub(crate) fn empty_stored_content() -> SanitizedStoredContent {
    SanitizedStoredContent {
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn sanitize_text(content: &str, redactor: &Redactor) -> String {
    // Normalize line endings before indexing. This keeps line ranges stable
    // across output produced by Unix and Windows commands.
    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    redactor.redact(&normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_boundary_redacts_and_normalizes_newlines() {
        let content = sanitize_for_storage("token=secret\r\nnext", "", &Redactor::new());
        assert_eq!(content.stdout(), "token=[REDACTED_SECRET]\nnext");
        assert!(!content.stdout().contains("secret"));
    }
}
