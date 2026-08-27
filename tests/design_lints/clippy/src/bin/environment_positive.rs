#[expect(
    clippy::disallowed_methods,
    reason = "DL-007: environment and current-directory reads are confined to the environment adapter"
)]
fn environment_adapter() {
    let _ = std::env::var("HOME");
    let _ = std::env::var_os("HOME");
    let _ = std::env::vars().count();
    let _ = std::env::vars_os().count();
    let _ = std::env::current_dir();
}

fn main() {
    environment_adapter();
}
