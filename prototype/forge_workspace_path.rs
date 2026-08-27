extern crate workspace_path_spike;

use std::path::PathBuf;
use workspace_path_spike::WorkspacePath;

fn main() {
    let _forged = WorkspacePath {
        canonical_target: PathBuf::from("/tmp/unverified"),
    };
}
