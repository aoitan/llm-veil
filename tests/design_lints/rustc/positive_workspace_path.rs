extern crate workspace_path_spike;

use workspace_path_spike::{Workspace, read_verified};

fn main() {
    let _ = Workspace::new(".")
        .and_then(|workspace| workspace.resolve("."))
        .and_then(|target| read_verified(&target));
}
