use std::path::Path;

mod path_guard {
    use std::path::Path;

    pub struct PathGuard;

    impl PathGuard {
        pub(crate) fn block_rule_for_path(&self, _path: &Path) -> Option<&str> {
            None
        }
    }
}

mod path_io {
    include!("../../../src/path_io.rs");
}

use path_io::{PathIo, WorkspaceResolver};

fn main() {
    let resolver = WorkspaceResolver::new(".").expect("fixture resolver");
    let raw_path = Path::new("Cargo.toml");
    let _ = resolver.read_file(raw_path);
}
