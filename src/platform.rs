#[cfg(test)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};

#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(target_os = "linux")]
use std::ffi::CString;

#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

// DL-001 unsafe island: libc calls that cannot be expressed through the safe
// standard-library API live in this platform adapter. Callers use the safe
// wrappers below and do not carry unsafe requirements into application code.

#[cfg(unix)]
static RECEIVED_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn record_shutdown_signal(signal: libc::c_int) {
    RECEIVED_SIGNAL.store(signal, Ordering::SeqCst);
}

#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "DL-001: installing process signal handlers is confined to the platform unsafe island"
)]
pub(crate) fn install_shutdown_signal_handlers() {
    // SAFETY: `record_shutdown_signal` has the C signal-handler ABI and only
    // performs an atomic store, which is async-signal-safe. SIGINT/SIGTERM
    // are valid signal numbers supplied by libc.
    unsafe {
        libc::signal(
            libc::SIGINT,
            record_shutdown_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            record_shutdown_signal as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(not(unix))]
pub(crate) fn install_shutdown_signal_handlers() {}

#[cfg(unix)]
pub(crate) fn reset_received_signal() {
    RECEIVED_SIGNAL.store(0, Ordering::SeqCst);
}

#[cfg(not(unix))]
pub(crate) fn reset_received_signal() {}

#[cfg(unix)]
pub(crate) fn received_signal() -> Option<i32> {
    let signal = RECEIVED_SIGNAL.load(Ordering::SeqCst);
    (signal > 0).then_some(signal)
}

#[cfg(not(unix))]
pub(crate) fn received_signal() -> Option<i32> {
    None
}

#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "DL-001: process-group termination is confined to the platform unsafe island"
)]
pub(crate) fn terminate_child(child: &mut Child) -> io::Result<()> {
    let pgid = child.id() as libc::pid_t;
    // SAFETY: `pgid` comes from the live child handle and `SIGKILL` is a valid
    // libc signal. The fallback preserves the existing child-only behavior if
    // the process group no longer exists.
    let kill_result = unsafe { libc::killpg(pgid, libc::SIGKILL) };
    if kill_result == -1 {
        child.kill()?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn terminate_child(child: &mut Child) -> io::Result<()> {
    child.kill()
}

#[cfg(all(unix, test))]
#[expect(
    unsafe_code,
    reason = "DL-001: signal delivery test hook is confined to the platform unsafe island"
)]
pub(crate) fn raise_signal_for_test(signal: libc::c_int) {
    // SAFETY: tests pass a valid process signal and intentionally exercise the
    // same signal-handler path used by command execution.
    unsafe {
        libc::raise(signal);
    }
}

/// Return the effective user id through the platform boundary.
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "DL-001: effective-user lookup is confined to the platform unsafe island"
)]
pub(crate) fn effective_user_id() -> u32 {
    // SAFETY: `geteuid` has no pointer or ownership preconditions and only
    // reads process credential state maintained by the operating system.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
pub(crate) fn effective_user_id() -> u32 {
    0
}

/// Publish a record without replacing an existing destination on Linux.
#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "DL-001: renameat2 no-replace syscall is confined to the platform unsafe island"
)]
pub(crate) fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "storage path contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "storage path contains NUL"))?;

    // SAFETY: both C strings are NUL-free, point to live path bytes for the
    // duration of the syscall, and use the documented renameat2 arguments.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Sources environment and process-platform state for application adapters.
///
/// Keeping these operations behind a small trait gives unit tests a way to
/// substitute deterministic values without mutating the process environment.
pub(crate) trait EnvironmentAdapter {
    fn value(&self, name: &str) -> Option<OsString>;

    fn variables(&self) -> Vec<(OsString, OsString)>;

    fn current_dir(&self) -> io::Result<PathBuf>;

    fn home_dir(&self) -> Option<PathBuf> {
        non_empty(self.value("HOME"))
            .or_else(|| non_empty(self.value("USERPROFILE")))
            .map(PathBuf::from)
    }

    fn xdg_data_home(&self) -> Option<PathBuf> {
        non_empty(self.value("XDG_DATA_HOME")).map(PathBuf::from)
    }

    #[cfg(any(test, target_os = "windows"))]
    fn local_app_data(&self) -> Option<PathBuf> {
        non_empty(self.value("LOCALAPPDATA")).map(PathBuf::from)
    }

    fn workspace_root(&self) -> io::Result<PathBuf> {
        non_empty(self.value("LLM_VEIL_WORKSPACE_ROOT"))
            .map(PathBuf::from)
            .map(Ok)
            .unwrap_or_else(|| self.current_dir())
    }
}

fn non_empty(value: Option<OsString>) -> Option<OsString> {
    value.filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemEnvironment;

impl EnvironmentAdapter for SystemEnvironment {
    #[expect(
        clippy::disallowed_methods,
        reason = "DL-007: raw environment reads are confined to the platform adapter"
    )]
    fn value(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "DL-007: raw environment enumeration is confined to the platform adapter"
    )]
    fn variables(&self) -> Vec<(OsString, OsString)> {
        std::env::vars_os().collect()
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "DL-007: current-directory resolution is confined to the platform adapter"
    )]
    fn current_dir(&self) -> io::Result<PathBuf> {
        std::env::current_dir()
    }
}

/// A validated command description passed to the process adapter.
///
/// The fields stay private so callers cannot bypass request construction or
/// make the system adapter accept an unvalidated empty argv.
#[derive(Debug)]
pub(crate) struct CommandRequest {
    arguments: Vec<String>,
    environment: Vec<(OsString, OsString)>,
}

impl CommandRequest {
    pub(crate) fn new(
        arguments: &[String],
        environment: Vec<(OsString, OsString)>,
    ) -> io::Result<Self> {
        if arguments.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Empty command arguments",
            ));
        }

        Ok(Self {
            arguments: arguments.to_vec(),
            environment,
        })
    }

    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

pub(crate) trait ProcessAdapter {
    fn spawn(&self, request: &CommandRequest) -> io::Result<Child>;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemProcessAdapter;

impl ProcessAdapter for SystemProcessAdapter {
    #[expect(
        clippy::disallowed_methods,
        clippy::disallowed_types,
        reason = "DL-002: process construction is confined to the platform adapter"
    )]
    fn spawn(&self, request: &CommandRequest) -> io::Result<Child> {
        use std::process::Command;

        let arguments = request.arguments();
        let mut command = Command::new(&arguments[0]);
        command.args(&arguments[1..]);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            command.process_group(0);
        }
        command.envs(request.environment.iter().map(|(key, value)| (key, value)));
        command.spawn()
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(crate) struct TestEnvironment {
    current_dir: PathBuf,
    values: Vec<(OsString, OsString)>,
}

#[cfg(test)]
impl TestEnvironment {
    pub(crate) fn new(current_dir: impl Into<PathBuf>) -> Self {
        Self {
            current_dir: current_dir.into(),
            values: Vec::new(),
        }
    }

    pub(crate) fn with_value(
        mut self,
        name: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Self {
        self.values.push((name.into(), value.into()));
        self
    }
}

#[cfg(test)]
impl EnvironmentAdapter for TestEnvironment {
    fn value(&self, name: &str) -> Option<OsString> {
        self.values
            .iter()
            .rev()
            .find(|(key, _)| key == OsStr::new(name))
            .map(|(_, value)| value.clone())
    }

    fn variables(&self) -> Vec<(OsString, OsString)> {
        self.values.clone()
    }

    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(self.current_dir.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_resolution_is_substitutable() {
        let environment = TestEnvironment::new("/fixture/current")
            .with_value("HOME", "/fixture/home")
            .with_value("XDG_DATA_HOME", "/fixture/data")
            .with_value("LOCALAPPDATA", "/fixture/local-app-data")
            .with_value("LLM_VEIL_WORKSPACE_ROOT", "/fixture/workspace");

        assert_eq!(environment.home_dir(), Some(PathBuf::from("/fixture/home")));
        assert_eq!(
            environment.xdg_data_home(),
            Some(PathBuf::from("/fixture/data"))
        );
        assert_eq!(
            environment.local_app_data(),
            Some(PathBuf::from("/fixture/local-app-data"))
        );
        assert_eq!(
            environment.workspace_root().unwrap(),
            PathBuf::from("/fixture/workspace")
        );
    }

    #[test]
    fn workspace_root_falls_back_to_injected_current_dir() {
        let environment = TestEnvironment::new("/fixture/current");

        assert_eq!(
            environment.workspace_root().unwrap(),
            PathBuf::from("/fixture/current")
        );
    }

    #[test]
    fn command_request_rejects_empty_arguments() {
        let error = CommandRequest::new(&[], Vec::new()).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "Empty command arguments");
    }
}
