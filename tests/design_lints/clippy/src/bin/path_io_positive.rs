use std::fs;

#[expect(
    clippy::disallowed_methods,
    reason = "DL-003 fixture: the path_io adapter is the only allowed read/walk scope"
)]
fn verified_path_io_adapter() {
    let _ = fs::canonicalize("fixture");
    let _ = std::path::Path::new("fixture").canonicalize();
    let _ = fs::read("fixture");
    let _ = fs::read_to_string("fixture");
    let _ = fs::read_dir("fixture");
    let _ = fs::File::open("fixture");
    let _ = fs::OpenOptions::new().read(true).open("fixture");
}

fn main() {
    verified_path_io_adapter();
}
