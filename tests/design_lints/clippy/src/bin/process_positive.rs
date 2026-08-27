#[expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "DL-002: process construction is confined to the process adapter"
)]
fn process_adapter() {
    use std::process::Command;

    let _ = Command::new("true");
}

fn main() {
    process_adapter();
}
