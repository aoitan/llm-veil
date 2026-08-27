mod config {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum PromptInjectionAction {
        Warn,
        Block,
    }
}

mod injector {
    pub(crate) struct Injector;

    impl Injector {
        pub(crate) fn detect_injection(&self, _content: &str) -> usize {
            0
        }
    }
}

mod redactor {
    pub(crate) struct Redactor;

    impl Redactor {
        pub(crate) fn redact(&self, content: &str) -> String {
            content.to_owned()
        }

        pub(crate) fn count_redactions(_before: &str, _after: &str) -> usize {
            0
        }
    }
}

mod utils {
    pub(crate) fn wrap_untrusted(content: &str) -> String {
        content.to_owned()
    }

    pub(crate) fn untrusted_payload_budget(max_chars: usize) -> usize {
        max_chars
    }

    pub(crate) fn fit_to_char_budget(content: &str, _max_chars: usize) -> (String, bool) {
        (content.to_owned(), false)
    }

    pub(crate) fn wrap_untrusted_bounded(content: &str, _max_chars: usize) -> String {
        content.to_owned()
    }
}

mod output {
    include!("../../../src/output.rs");
}

use output::ExternalRender;

fn main() {
    let _forged = ExternalRender {
        content: Some("untrusted".to_owned()),
        redactions: 0,
        injection_warnings: 0,
        blocked: false,
        truncated: false,
    };
}
