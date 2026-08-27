mod redactor {
    pub(crate) struct Redactor;

    impl Redactor {
        pub(crate) fn redact(&self, content: &str) -> String {
            content.to_owned()
        }
    }
}

mod safety {
    include!("../../../src/safety.rs");
}

mod stats {
    pub(crate) struct Stats {
        pub(crate) run_id: String,
    }
}

mod platform {
    pub(crate) trait EnvironmentAdapter {}

    pub(crate) struct SystemEnvironment;

    impl EnvironmentAdapter for SystemEnvironment {}
}

mod storage {
    use crate::safety::SanitizedStoredContent;
    use crate::stats::Stats;
    use std::io;

    #[derive(Clone)]
    pub(crate) enum StorageReason {
        Stored,
        NoStore,
        StorageUnavailable,
        QuotaExceeded,
    }

    pub(crate) struct StorageReceipt {
        pub(crate) run_id: String,
        pub(crate) stored: bool,
        pub(crate) retrievable: bool,
        pub(crate) reason: StorageReason,
        pub(crate) expires_at: Option<i64>,
    }

    pub(crate) struct RunStore;

    impl RunStore {
        pub(crate) fn open_default() -> io::Result<Self> {
            Ok(Self)
        }

        pub(crate) fn open_default_with(
            _environment: &dyn crate::platform::EnvironmentAdapter,
        ) -> io::Result<Self> {
            Ok(Self)
        }

        pub(crate) fn commit(
            &mut self,
            _stats: &Stats,
            _content: &SanitizedStoredContent,
            _command_kind: &str,
        ) -> io::Result<i64> {
            Ok(0)
        }
    }
}

mod persistence {
    include!("../../../src/persistence.rs");
}
