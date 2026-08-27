#[expect(
    clippy::disallowed_methods,
    reason = "DL-003 fixture: this file is not an approved production scope"
)]
fn unregistered_scope() {}

fn main() {
    unregistered_scope();
}
