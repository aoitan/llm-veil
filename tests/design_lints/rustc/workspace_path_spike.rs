use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Workspace {
    canonical_root: PathBuf,
}

#[derive(Debug)]
pub struct WorkspacePath {
    canonical_target: PathBuf,
}

impl Workspace {
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            canonical_root: root.as_ref().canonicalize()?,
        })
    }

    pub fn resolve(&self, raw: impl AsRef<Path>) -> io::Result<WorkspacePath> {
        let raw = raw.as_ref();
        let candidate = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            self.canonical_root.join(raw)
        };
        let canonical_target = candidate.canonicalize()?;
        if !canonical_target.starts_with(&self.canonical_root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target is outside workspace",
            ));
        }
        Ok(WorkspacePath { canonical_target })
    }
}

pub fn read_verified(path: &WorkspacePath) -> io::Result<String> {
    fs::read_to_string(&path.canonical_target)
}
