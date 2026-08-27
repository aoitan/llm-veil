use crate::platform::EnvironmentAdapter;
use crate::safety::SanitizedStoredContent;
use crate::stats::Stats;
use crate::storage::{RunStore, StorageReason, StorageReceipt};
use std::io;

/// The only application-facing capability for durable content writes.
///
/// The facade accepts an opaque, already-sanitized value by shared reference.
/// Raw strings never cross this API, and the storage implementation remains
/// responsible only for persistence, quotas, and filesystem guarantees.
pub(crate) struct Persistence {
    backend: Option<RunStore>,
    reason: StorageReason,
}

impl Persistence {
    pub(crate) fn new_with_environment(
        no_store: bool,
        environment: &dyn EnvironmentAdapter,
    ) -> Self {
        if no_store {
            return Self {
                backend: None,
                reason: StorageReason::NoStore,
            };
        }

        match RunStore::open_default_with(environment) {
            Ok(backend) => Self {
                backend: Some(backend),
                reason: StorageReason::Stored,
            },
            Err(_) => Self {
                backend: None,
                reason: StorageReason::StorageUnavailable,
            },
        }
    }

    #[cfg(test)]
    fn from_backend(backend: RunStore) -> Self {
        Self {
            backend: Some(backend),
            reason: StorageReason::Stored,
        }
    }

    /// Persist only content that has crossed the storage safety boundary.
    pub(crate) fn store(
        &mut self,
        stats: &Stats,
        content: &SanitizedStoredContent,
        command_kind: &str,
    ) -> StorageReceipt {
        let run_id = stats.run_id.clone();
        let Some(backend) = self.backend.as_mut() else {
            return StorageReceipt {
                run_id,
                stored: false,
                retrievable: false,
                reason: self.reason.clone(),
                expires_at: None,
            };
        };

        match backend.commit(stats, content, command_kind) {
            Ok(expires_at) => StorageReceipt {
                run_id,
                stored: true,
                retrievable: true,
                reason: StorageReason::Stored,
                expires_at: Some(expires_at),
            },
            Err(error) => StorageReceipt {
                run_id,
                stored: false,
                retrievable: false,
                reason: if error.kind() == io::ErrorKind::StorageFull
                    || error.to_string().starts_with("quota:")
                {
                    StorageReason::QuotaExceeded
                } else {
                    StorageReason::StorageUnavailable
                },
                expires_at: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redactor::Redactor;
    use chrono::Utc;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[expect(
        clippy::disallowed_methods,
        reason = "DL-003: persistence fixture resolves its temporary parent directory"
    )]
    fn temp_root() -> PathBuf {
        std::env::temp_dir()
            .canonicalize()
            .expect("canonicalize temporary directory")
            .join(format!("llm-veil-persistence-{}", Uuid::new_v4()))
    }

    fn stats(run_id: Uuid) -> Stats {
        Stats {
            run_id: run_id.to_string(),
            command: Some("run -- fixture".to_owned()),
            exit_code: Some(0),
            raw_bytes: 32,
            returned_bytes: 16,
            reduction: 50.0,
            redactions: 1,
            prompt_injection_warnings: 0,
            truncated: false,
            timeout: false,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "DL-003: persistence fixture inspects the sanitized record"
    )]
    fn facade_persists_only_sanitized_content() {
        let root = temp_root();
        let backend = RunStore::open(root.clone()).expect("open test storage");
        let mut persistence = Persistence::from_backend(backend);
        let run_id = Uuid::new_v4();
        let stats = stats(run_id);
        let content = crate::safety::sanitize_for_storage(
            "stdout password=known-secret",
            "stderr",
            &Redactor::new(),
        );

        let receipt = persistence.store(&stats, &content, "run");

        assert_eq!(receipt.run_id, run_id.to_string());
        assert_eq!(receipt.reason, StorageReason::Stored);
        assert!(receipt.stored);
        assert!(receipt.retrievable);

        let record_dir = root.join("records").join(run_id.to_string());
        let mut saw_redacted_content = false;
        for entry in fs::read_dir(record_dir).expect("read persisted record") {
            let bytes = fs::read(entry.expect("read record entry").path()).expect("read record");
            let persisted = String::from_utf8_lossy(&bytes);
            assert!(!persisted.contains("known-secret"));
            saw_redacted_content |= persisted.contains("[REDACTED_SECRET]");
        }
        assert!(saw_redacted_content);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn facade_reports_backend_rejection_without_falling_back_to_raw_content() {
        let root = temp_root();
        let backend = RunStore::open(root.clone()).expect("open test storage");
        let mut persistence = Persistence::from_backend(backend);
        let mut stats = stats(Uuid::new_v4());
        stats.run_id = "not-a-uuid".to_owned();
        let content =
            crate::safety::sanitize_for_storage("password=known-secret", "", &Redactor::new());

        let receipt = persistence.store(&stats, &content, "run");

        assert_eq!(receipt.reason, StorageReason::StorageUnavailable);
        assert!(!receipt.stored);
        assert!(!receipt.retrievable);
        assert!(!root.join("records").join("not-a-uuid").exists());

        let _ = fs::remove_dir_all(root);
    }
}
