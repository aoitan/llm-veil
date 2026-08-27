use std::path::PathBuf;

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

use path_io::ExistingWorkspaceFile;

fn main() {
    let _forged = ExistingWorkspaceFile {
        canonical_target: PathBuf::from("/tmp/unverified"),
        display_label: PathBuf::from("/tmp/unverified"),
    };
}
