include!("storage_content_support.rs");

fn main() {
    let _forged = safety::SanitizedStoredContent {
        stdout: "raw content".to_owned(),
        stderr: String::new(),
    };
}
