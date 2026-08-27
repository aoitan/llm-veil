use crate::path_guard::PathGuard;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Component, Path, PathBuf};

/// The only existing target kinds that the read boundary can issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExistingTargetKind {
    File,
    Directory,
}

/// Errors raised before a path becomes a usable read capability.
///
/// Display intentionally omits the raw and canonical path. Callers may use
/// the variants for internal handling, but externally visible errors should
/// be rendered by the caller's sanitized output boundary.
#[derive(Debug)]
pub(crate) enum PathBoundaryError {
    WorkspaceRoot(io::Error),
    PolicyDenied {
        rule: String,
    },
    OutsideWorkspace,
    SymlinkNotAllowed,
    NotFound(io::Error),
    WrongTargetKind {
        expected: ExistingTargetKind,
        actual: ExistingTargetKind,
    },
    UnsupportedFileType,
    Io(io::Error),
}

impl fmt::Display for PathBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceRoot(_) => formatter.write_str("workspace root could not be resolved"),
            Self::PolicyDenied { .. } => {
                formatter.write_str("path was denied by the configured path policy")
            }
            Self::OutsideWorkspace => formatter.write_str("path is outside the workspace"),
            Self::SymlinkNotAllowed => {
                formatter.write_str("symbolic links are not allowed for existing targets")
            }
            Self::NotFound(_) => formatter.write_str("path does not exist"),
            Self::WrongTargetKind { expected, actual } => {
                write!(formatter, "expected {expected:?}, found {actual:?}")
            }
            Self::UnsupportedFileType => formatter.write_str("unsupported file type"),
            Self::Io(_) => formatter.write_str("path I/O failed"),
        }
    }
}

impl Error for PathBoundaryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::WorkspaceRoot(error) | Self::NotFound(error) | Self::Io(error) => Some(error),
            Self::PolicyDenied { .. }
            | Self::OutsideWorkspace
            | Self::SymlinkNotAllowed
            | Self::WrongTargetKind { .. }
            | Self::UnsupportedFileType => None,
        }
    }
}

impl PathBoundaryError {
    pub(crate) fn policy_rule(&self) -> Option<&str> {
        match self {
            Self::PolicyDenied { rule } => Some(rule),
            _ => None,
        }
    }

    pub(crate) fn is_workspace_boundary(&self) -> bool {
        matches!(self, Self::OutsideWorkspace)
    }
}

/// A read capability for an existing regular file inside the workspace.
///
/// Both fields are private so callers cannot forge a capability or recover a
/// raw path for an unrelated I/O operation. `display_label` is retained only
/// for a future diagnostic adapter and is never used for opening the file.
#[derive(Debug)]
pub(crate) struct ExistingWorkspaceFile {
    canonical_target: PathBuf,
    display_label: PathBuf,
}

/// A read capability for an existing directory inside the workspace.
#[derive(Debug)]
pub(crate) struct ExistingWorkspaceDir {
    canonical_target: PathBuf,
    display_label: PathBuf,
}

#[derive(Debug)]
pub(crate) enum ExistingWorkspaceTarget {
    File(ExistingWorkspaceFile),
    Dir(ExistingWorkspaceDir),
}

/// Resolves raw input into read-only capabilities rooted at one canonical
/// workspace directory.
#[derive(Debug)]
pub(crate) struct WorkspaceResolver {
    canonical_root: PathBuf,
}

impl WorkspaceResolver {
    #[expect(
        clippy::disallowed_methods,
        reason = "DL-003: path_io owns canonical workspace-root resolution"
    )]
    pub(crate) fn new<P: AsRef<Path>>(root: P) -> Result<Self, PathBoundaryError> {
        let canonical_root =
            fs::canonicalize(root.as_ref()).map_err(PathBoundaryError::WorkspaceRoot)?;
        let root_metadata =
            fs::metadata(&canonical_root).map_err(PathBoundaryError::WorkspaceRoot)?;
        let root_kind = classify_target_kind(&root_metadata)?;
        if root_kind != ExistingTargetKind::Directory {
            return Err(PathBoundaryError::WrongTargetKind {
                expected: ExistingTargetKind::Directory,
                actual: root_kind,
            });
        }

        Ok(Self { canonical_root })
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "DL-003: path_io owns canonical workspace-target resolution"
    )]
    pub(crate) fn resolve_existing<P: AsRef<Path>>(
        &self,
        raw: P,
        path_guard: &PathGuard,
    ) -> Result<ExistingWorkspaceTarget, PathBoundaryError> {
        let raw = raw.as_ref();

        if let Some(rule) = path_guard.block_rule_for_path(raw) {
            return Err(PathBoundaryError::PolicyDenied {
                rule: rule.to_owned(),
            });
        }

        let candidate = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            self.canonical_root.join(raw)
        };
        let canonical_target = fs::canonicalize(&candidate).map_err(classify_target_io)?;

        if !canonical_target.starts_with(&self.canonical_root) {
            return Err(PathBoundaryError::OutsideWorkspace);
        }

        if let Some(rule) = path_guard.block_rule_for_path(&canonical_target) {
            return Err(PathBoundaryError::PolicyDenied {
                rule: rule.to_owned(),
            });
        }

        // The canonical policy remains higher priority than the symlink
        // policy. This preserves the existing contract for a safe-looking
        // link whose target is a blocked path, while still rejecting links to
        // otherwise allowed targets below.
        //
        // The canonical target alone cannot tell whether the requested
        // spelling crossed a symlink. Inspect the original candidate before
        // issuing a capability so direct and intermediate links are rejected.
        if contains_symlink_component(&candidate).map_err(classify_target_io)? {
            return Err(PathBoundaryError::SymlinkNotAllowed);
        }

        let metadata = fs::metadata(&canonical_target).map_err(classify_target_io)?;
        let target_kind = classify_target_kind(&metadata)?;
        let display_label = raw.to_path_buf();

        Ok(match target_kind {
            ExistingTargetKind::File => ExistingWorkspaceTarget::File(ExistingWorkspaceFile {
                canonical_target,
                display_label,
            }),
            ExistingTargetKind::Directory => ExistingWorkspaceTarget::Dir(ExistingWorkspaceDir {
                canonical_target,
                display_label,
            }),
        })
    }

    pub(crate) fn resolve_existing_file<P: AsRef<Path>>(
        &self,
        raw: P,
        path_guard: &PathGuard,
    ) -> Result<ExistingWorkspaceFile, PathBoundaryError> {
        match self.resolve_existing(raw, path_guard)? {
            ExistingWorkspaceTarget::File(file) => Ok(file),
            ExistingWorkspaceTarget::Dir(_) => Err(PathBoundaryError::WrongTargetKind {
                expected: ExistingTargetKind::File,
                actual: ExistingTargetKind::Directory,
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn resolve_existing_dir<P: AsRef<Path>>(
        &self,
        raw: P,
        path_guard: &PathGuard,
    ) -> Result<ExistingWorkspaceDir, PathBoundaryError> {
        match self.resolve_existing(raw, path_guard)? {
            ExistingWorkspaceTarget::File(_) => Err(PathBoundaryError::WrongTargetKind {
                expected: ExistingTargetKind::Directory,
                actual: ExistingTargetKind::File,
            }),
            ExistingWorkspaceTarget::Dir(directory) => Ok(directory),
        }
    }
}

/// I/O operations accept only capabilities issued by `WorkspaceResolver`.
pub(crate) trait PathIo {
    fn read_file(&self, file: &ExistingWorkspaceFile) -> io::Result<Vec<u8>>;

    fn grep(
        &self,
        target: ExistingWorkspaceTarget,
        pattern: &str,
        path_guard: &PathGuard,
    ) -> io::Result<GrepOutcome>;
}

#[derive(Debug)]
pub(crate) struct GrepMatch {
    pub(crate) display_path: PathBuf,
    pub(crate) line_number: usize,
    pub(crate) content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TraversalCompleteness {
    Complete,
    Partial,
}

impl TraversalCompleteness {
    pub(crate) fn is_partial(self) -> bool {
        matches!(self, Self::Partial)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TraversalDiagnosticKind {
    SymlinkSkipped,
    EntryUnreadable,
    FileUnreadable,
    UnsupportedFileType,
    ResourceLimitReached,
}

impl TraversalDiagnosticKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::SymlinkSkipped => "symlink_skipped",
            Self::EntryUnreadable => "entry_unreadable",
            Self::FileUnreadable => "file_unreadable",
            Self::UnsupportedFileType => "unsupported_file_type",
            Self::ResourceLimitReached => "resource_limit_reached",
        }
    }
}

#[derive(Debug)]
pub(crate) struct TraversalDiagnostic {
    kind: TraversalDiagnosticKind,
    display_path: PathBuf,
}

impl TraversalDiagnostic {
    pub(crate) fn kind(&self) -> TraversalDiagnosticKind {
        self.kind
    }

    pub(crate) fn display_path(&self) -> &Path {
        &self.display_path
    }
}

#[derive(Debug)]
pub(crate) struct GrepOutcome {
    pub(crate) matches: Vec<GrepMatch>,
    pub(crate) completeness: TraversalCompleteness,
    pub(crate) diagnostics: Vec<TraversalDiagnostic>,
}

impl PathIo for WorkspaceResolver {
    #[expect(
        clippy::disallowed_methods,
        reason = "DL-003: path_io reads only the private canonical file capability"
    )]
    fn read_file(&self, file: &ExistingWorkspaceFile) -> io::Result<Vec<u8>> {
        // The path comes from the private canonical target, never from the
        // display label or the raw input spelling. A hostile concurrent
        // filesystem remains outside this initial capability guarantee.
        fs::read(&file.canonical_target)
    }

    fn grep(
        &self,
        target: ExistingWorkspaceTarget,
        pattern: &str,
        path_guard: &PathGuard,
    ) -> io::Result<GrepOutcome> {
        let mut state = GrepState::new(pattern, path_guard);

        match target {
            ExistingWorkspaceTarget::File(file) => {
                state.scan_file(&file.canonical_target, &file.display_label);
            }
            ExistingWorkspaceTarget::Dir(directory) => {
                state.scan_root_directory(&directory.canonical_target, &directory.display_label)?;
            }
        }

        Ok(state.finish())
    }
}

const MAX_TRAVERSAL_DEPTH: usize = 64;
const MAX_TRAVERSAL_ENTRIES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 64;

struct GrepState<'a> {
    pattern: &'a str,
    path_guard: &'a PathGuard,
    matches: Vec<GrepMatch>,
    diagnostics: Vec<TraversalDiagnostic>,
    diagnostics_capped: bool,
    entries_seen: usize,
    partial: bool,
}

impl<'a> GrepState<'a> {
    fn new(pattern: &'a str, path_guard: &'a PathGuard) -> Self {
        Self {
            pattern,
            path_guard,
            matches: Vec::new(),
            diagnostics: Vec::new(),
            diagnostics_capped: false,
            entries_seen: 0,
            partial: false,
        }
    }

    fn finish(self) -> GrepOutcome {
        GrepOutcome {
            matches: self.matches,
            completeness: if self.partial {
                TraversalCompleteness::Partial
            } else {
                TraversalCompleteness::Complete
            },
            diagnostics: self.diagnostics,
        }
    }

    fn record(&mut self, kind: TraversalDiagnosticKind, display_path: &Path) {
        self.partial = true;
        if self.diagnostics.len() < MAX_DIAGNOSTICS {
            self.diagnostics.push(TraversalDiagnostic {
                kind,
                display_path: display_path.to_path_buf(),
            });
        } else if !self.diagnostics_capped {
            // Keep the diagnostic list bounded while making the fact that
            // additional failures were suppressed machine-observable.
            if let Some(last) = self.diagnostics.last_mut() {
                *last = TraversalDiagnostic {
                    kind: TraversalDiagnosticKind::ResourceLimitReached,
                    display_path: display_path.to_path_buf(),
                };
            }
            self.diagnostics_capped = true;
        }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "DL-003: path_io opens files discovered by the verified walker"
    )]
    fn scan_root_directory(&mut self, canonical_dir: &Path, display_dir: &Path) -> io::Result<()> {
        let entries = fs::read_dir(canonical_dir)?;
        self.scan_directory_entries(entries, display_dir, 0);
        Ok(())
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "DL-003: path_io opens files discovered by the verified walker"
    )]
    fn scan_child_directory(&mut self, canonical_dir: &Path, display_dir: &Path, depth: usize) {
        let entries = match fs::read_dir(canonical_dir) {
            Ok(entries) => entries,
            Err(_) => {
                self.record(TraversalDiagnosticKind::EntryUnreadable, display_dir);
                return;
            }
        };
        self.scan_directory_entries(entries, display_dir, depth);
    }

    fn scan_directory_entries(&mut self, entries: fs::ReadDir, display_dir: &Path, depth: usize) {
        for entry_result in entries {
            if self.entries_seen >= MAX_TRAVERSAL_ENTRIES {
                self.record(TraversalDiagnosticKind::ResourceLimitReached, display_dir);
                break;
            }
            self.entries_seen += 1;

            let entry = match entry_result {
                Ok(entry) => entry,
                Err(_) => {
                    self.record(TraversalDiagnosticKind::EntryUnreadable, display_dir);
                    continue;
                }
            };

            let canonical_path = entry.path();
            let display_path = display_dir.join(entry.file_name());
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    self.record(TraversalDiagnosticKind::EntryUnreadable, &display_path);
                    continue;
                }
            };

            if file_type.is_symlink() {
                self.record(TraversalDiagnosticKind::SymlinkSkipped, &display_path);
                continue;
            }

            if self.path_guard.block_rule_for_path(&display_path).is_some() {
                continue;
            }

            if file_type.is_dir() {
                if depth >= MAX_TRAVERSAL_DEPTH {
                    self.record(TraversalDiagnosticKind::ResourceLimitReached, &display_path);
                    continue;
                }
                self.scan_child_directory(&canonical_path, &display_path, depth + 1);
            } else if file_type.is_file() {
                self.scan_file(&canonical_path, &display_path);
            } else {
                self.record(TraversalDiagnosticKind::UnsupportedFileType, &display_path);
            }
        }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "DL-003: path_io opens files discovered by the verified walker"
    )]
    fn scan_file(&mut self, canonical_path: &Path, display_path: &Path) {
        let metadata = match fs::symlink_metadata(canonical_path) {
            Ok(metadata) => metadata,
            Err(_) => {
                self.record(TraversalDiagnosticKind::FileUnreadable, display_path);
                return;
            }
        };

        if metadata.file_type().is_symlink() {
            self.record(TraversalDiagnosticKind::SymlinkSkipped, display_path);
            return;
        }
        if !metadata.file_type().is_file() {
            self.record(TraversalDiagnosticKind::UnsupportedFileType, display_path);
            return;
        }
        if metadata.len() > MAX_FILE_BYTES {
            self.record(TraversalDiagnosticKind::ResourceLimitReached, display_path);
            return;
        }

        let file = match fs::File::open(canonical_path) {
            Ok(file) => file,
            Err(_) => {
                self.record(TraversalDiagnosticKind::FileUnreadable, display_path);
                return;
            }
        };
        let reader = BufReader::new(file);

        for (line_index, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(line) => line,
                Err(_) => {
                    self.record(TraversalDiagnosticKind::FileUnreadable, display_path);
                    break;
                }
            };

            if line.contains(self.pattern) {
                self.matches.push(GrepMatch {
                    display_path: display_path.to_path_buf(),
                    line_number: line_index + 1,
                    content: line,
                });
            }
        }
    }
}

fn classify_target_kind(metadata: &fs::Metadata) -> Result<ExistingTargetKind, PathBoundaryError> {
    let file_type = metadata.file_type();
    if file_type.is_file() {
        Ok(ExistingTargetKind::File)
    } else if file_type.is_dir() {
        Ok(ExistingTargetKind::Directory)
    } else {
        Err(PathBoundaryError::UnsupportedFileType)
    }
}

fn classify_target_io(error: io::Error) -> PathBoundaryError {
    if error.kind() == io::ErrorKind::NotFound {
        PathBoundaryError::NotFound(error)
    } else {
        PathBoundaryError::Io(error)
    }
}

/// Return whether any existing component in `path` is a symlink.
///
/// `symlink_metadata` inspects each component without following the final
/// component. Once a missing component is encountered, canonicalization will
/// provide the authoritative not-found error, so there is no later existing
/// component to inspect.
fn contains_symlink_component(path: &Path) -> io::Result<bool> {
    let mut current = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => current.push(component.as_os_str()),
            Component::Normal(part) => {
                current.push(part);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                    Err(error) => return Err(error),
                }
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_guard::{PathAction, PathGuard};
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        #[expect(
            clippy::disallowed_methods,
            reason = "DL-003: path boundary fixtures use a canonical temporary root"
        )]
        fn new(label: &str) -> Self {
            let temp_root =
                fs::canonicalize(std::env::temp_dir()).expect("canonicalize temporary directory");
            let id = Uuid::new_v4().to_string();
            let path = temp_root.join(format!("pio-{label}-{}", &id[..8]));
            fs::create_dir(&path).expect("create path boundary fixture");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn allow_guard() -> PathGuard {
        PathGuard::new(Vec::new(), PathAction::Allow).expect("create allow path guard")
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "DL-003: path boundary test compares the canonical fixture target"
    )]
    fn resolves_and_reads_existing_file_without_reopening_raw_spelling() {
        let root = TempDir::new("read");
        let file_path = root.path().join("nested.txt");
        fs::write(&file_path, "verified content").expect("write path fixture");

        let resolver = WorkspaceResolver::new(root.path()).expect("create resolver");
        let file = resolver
            .resolve_existing_file(&file_path, &allow_guard())
            .expect("resolve file capability");

        assert_eq!(file.canonical_target, file_path.canonicalize().unwrap());
        assert_eq!(resolver.read_file(&file).unwrap(), b"verified content");
        assert_eq!(file.display_label, file_path);
    }

    #[test]
    fn grep_reports_an_oversized_capability_target_as_partial() {
        let root = TempDir::new("size-limit");
        let file_path = root.path().join("large.txt");
        fs::write(&file_path, vec![b'x'; (MAX_FILE_BYTES + 1) as usize])
            .expect("write oversized grep fixture");

        let resolver = WorkspaceResolver::new(root.path()).expect("create resolver");
        let file = resolver
            .resolve_existing_file(&file_path, &allow_guard())
            .expect("resolve oversized file capability");
        let outcome = resolver
            .grep(ExistingWorkspaceTarget::File(file), "x", &allow_guard())
            .expect("grep oversized file capability");

        assert_eq!(outcome.completeness, TraversalCompleteness::Partial);
        assert_eq!(outcome.matches.len(), 0);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].kind(),
            TraversalDiagnosticKind::ResourceLimitReached
        );
    }

    #[test]
    fn rejects_outside_and_parent_traversal_targets() {
        let root = TempDir::new("root");
        let outside = TempDir::new("outside");
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, "outside").expect("write outside fixture");
        let resolver = WorkspaceResolver::new(root.path()).expect("create resolver");
        let guard = allow_guard();

        assert!(matches!(
            resolver.resolve_existing(&outside_file, &guard),
            Err(PathBoundaryError::OutsideWorkspace)
        ));

        let traversal = root
            .path()
            .join("..")
            .join(outside.path().file_name().unwrap())
            .join("outside.txt");
        assert!(matches!(
            resolver.resolve_existing(traversal, &guard),
            Err(PathBoundaryError::OutsideWorkspace)
        ));
    }

    #[test]
    fn applies_raw_and_canonical_path_policy_before_issuing_capability() {
        let root = TempDir::new("policy");
        let file_path = root.path().join("allowed.txt");
        fs::write(&file_path, "content").expect("write policy fixture");
        let root_name = root.path().file_name().unwrap().to_string_lossy();
        let guard = PathGuard::new(vec![format!("{root_name}/")], PathAction::Block)
            .expect("create blocking path guard");
        let resolver = WorkspaceResolver::new(root.path()).expect("create resolver");

        assert!(matches!(
            resolver.resolve_existing(Path::new("allowed.txt"), &guard),
            Err(PathBoundaryError::PolicyDenied { .. })
        ));
    }

    #[test]
    fn rejects_file_directory_kind_mismatches() {
        let root = TempDir::new("kind");
        let file_path = root.path().join("file.txt");
        let directory_path = root.path().join("directory");
        fs::write(&file_path, "content").expect("write kind fixture");
        fs::create_dir(&directory_path).expect("create kind directory");
        let resolver = WorkspaceResolver::new(root.path()).expect("create resolver");
        let guard = allow_guard();

        assert!(matches!(
            resolver.resolve_existing_dir(&file_path, &guard),
            Err(PathBoundaryError::WrongTargetKind {
                expected: ExistingTargetKind::Directory,
                actual: ExistingTargetKind::File,
            })
        ));
        assert!(matches!(
            resolver.resolve_existing_file(&directory_path, &guard),
            Err(PathBoundaryError::WrongTargetKind {
                expected: ExistingTargetKind::File,
                actual: ExistingTargetKind::Directory,
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_direct_and_intermediate_symlinks() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new("symlink");
        let real_dir = root.path().join("real");
        let real_file = real_dir.join("file.txt");
        fs::create_dir(&real_dir).expect("create real directory");
        fs::write(&real_file, "content").expect("write real file");
        let direct_link = root.path().join("direct-link.txt");
        let intermediate_link = root.path().join("intermediate-link");
        symlink(&real_file, &direct_link).expect("create direct symlink");
        symlink(&real_dir, &intermediate_link).expect("create intermediate symlink");
        let resolver = WorkspaceResolver::new(root.path()).expect("create resolver");
        let guard = allow_guard();

        assert!(matches!(
            resolver.resolve_existing(&direct_link, &guard),
            Err(PathBoundaryError::SymlinkNotAllowed)
        ));
        assert!(matches!(
            resolver.resolve_existing(intermediate_link.join("file.txt"), &guard),
            Err(PathBoundaryError::SymlinkNotAllowed)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn canonicalizes_workspace_root_alias_but_rejects_target_aliases() {
        use std::os::unix::fs::symlink;

        let parent = TempDir::new("root-alias-parent");
        let actual_root = parent.path().join("workspace");
        let root_alias = parent.path().join("workspace-link");
        fs::create_dir(&actual_root).expect("create aliased workspace");
        symlink(&actual_root, &root_alias).expect("create workspace root symlink");

        let real_file = actual_root.join("file.txt");
        let target_alias = actual_root.join("file-link.txt");
        fs::write(&real_file, "content").expect("write aliased workspace file");
        symlink(&real_file, &target_alias).expect("create target symlink");

        let resolver = WorkspaceResolver::new(&root_alias).expect("resolve workspace root alias");
        let guard = allow_guard();
        assert!(resolver.resolve_existing_file(&real_file, &guard).is_ok());
        assert!(matches!(
            resolver.resolve_existing(&target_alias, &guard),
            Err(PathBoundaryError::SymlinkNotAllowed)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_untyped_unix_special_files() {
        use std::os::unix::net::UnixListener;

        let root = TempDir::new("special");
        let socket_path = root.path().join("s");
        let listener = UnixListener::bind(&socket_path).expect("create socket fixture");
        let resolver = WorkspaceResolver::new(root.path()).expect("create resolver");

        assert!(matches!(
            resolver.resolve_existing(&socket_path, &allow_guard()),
            Err(PathBoundaryError::UnsupportedFileType)
        ));
        drop(listener);
    }
}
