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

use config::PromptInjectionAction;
use injector::Injector;
use output::{render_external, OutputAdapter};
use redactor::Redactor;

#[derive(Default)]
struct FixtureOutputAdapter {
    stdout: Vec<u8>,
}

impl output::OutputAdapter for FixtureOutputAdapter {
    fn emit_stdout(&mut self, render: &output::ExternalRender) -> std::io::Result<()> {
        if let Some(content) = render.content() {
            self.stdout.extend_from_slice(content.as_bytes());
        }
        Ok(())
    }

    fn emit_stderr(&mut self, _render: &output::ExternalRender) -> std::io::Result<()> {
        Ok(())
    }
}

fn main() {
    let render = render_external(
        "safe fixture",
        &Redactor,
        &Injector,
        PromptInjectionAction::Warn,
        128,
    );
    let mut adapter = FixtureOutputAdapter::default();
    adapter.emit_stdout(&render).expect("fixture output");
}
