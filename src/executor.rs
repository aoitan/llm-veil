use crate::injector::Injector;
use crate::path_guard::PathGuard;
use crate::platform::{
    CommandRequest, EnvironmentAdapter, ProcessAdapter, install_shutdown_signal_handlers,
    received_signal, reset_received_signal, terminate_child,
};
#[cfg(test)]
use crate::platform::{SystemEnvironment, SystemProcessAdapter};
use crate::redactor::Redactor;
use crate::stats::Stats;
use crate::truncator::truncate;
use chrono::Utc;
use std::ffi::OsString;
use std::io::{self, Read};
use std::time::{Duration, Instant};
use uuid::Uuid;
use wait_timeout::ChildExt;

#[derive(Debug)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    /// Redacted, truncate-before output used by the retention layer.
    pub stored_stdout: String,
    pub stored_stderr: String,
    pub stats: Stats,
}

#[cfg(test)]
pub fn execute_command(
    command_args: &[String],
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    timeout_duration: Duration,
    max_chars: usize,
) -> Result<ExecutionResult, io::Error> {
    let environment = SystemEnvironment;
    let process = SystemProcessAdapter;
    execute_command_with_adapters(
        command_args,
        path_guard,
        redactor,
        injector,
        timeout_duration,
        max_chars,
        &environment,
        &process,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "WB-15-006: preserve the adapter seam until the application context refactor"
)]
pub(crate) fn execute_command_with_adapters(
    command_args: &[String],
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    timeout_duration: Duration,
    max_chars: usize,
    environment: &dyn EnvironmentAdapter,
    process: &dyn ProcessAdapter,
) -> Result<ExecutionResult, io::Error> {
    reset_received_signal();
    install_shutdown_signal_handlers();

    if command_args.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Empty command arguments",
        ));
    }

    // 危険パスのブロックチェック
    for arg in command_args {
        if path_guard.should_block(arg) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Access to blocked path was denied",
            ));
        }
    }

    let (sanitized_env, env_redactions) = sanitized_environment(environment, redactor);
    let request = CommandRequest::new(command_args, sanitized_env)?;
    let mut child = process.spawn(&request)?;

    let mut timeout = false;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();

    let deadline = Instant::now() + timeout_duration;
    let exit_code = loop {
        if let Some(signal) = received_signal() {
            let _ = terminate_child(&mut child);
            let _ = child.wait();
            break Some(128 + signal);
        }

        let now = Instant::now();
        if now >= deadline {
            timeout = true;
            terminate_child(&mut child)?;
            let _ = child.wait(); // ゾンビプロセス化を防ぐ
            break Some(124);
        }

        let wait_for = (deadline - now).min(Duration::from_millis(50));
        if let Some(status) = child.wait_timeout(wait_for)? {
            break status
                .code()
                .or_else(|| received_signal().map(|signal| 128 + signal));
        }
    };

    // 終了、タイムアウト、中断のどの場合も同じ最終サニタイズ経路に渡す。
    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_end(&mut stdout_bytes)?;
    }
    if let Some(mut stderr) = child.stderr.take() {
        stderr.read_to_end(&mut stderr_bytes)?;
    }

    let raw_stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let raw_stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

    // Redact (置換) の適用
    let redacted_stdout = redactor.redact(&raw_stdout);
    let redacted_stderr = redactor.redact(&raw_stderr);

    let redactions = Redactor::count_redactions(&raw_stdout, &redacted_stdout)
        + Redactor::count_redactions(&raw_stderr, &redacted_stderr)
        + env_redactions;

    // インジェクションの検出
    let prompt_injection_warnings =
        injector.detect_injection(&redacted_stdout) + injector.detect_injection(&redacted_stderr);

    let final_stdout = truncate(&redacted_stdout, max_chars);
    let final_stderr = truncate(&redacted_stderr, max_chars);

    let raw_bytes = raw_stdout.len() + raw_stderr.len();
    let returned_bytes = final_stdout.len() + final_stderr.len();

    let reduction = if raw_bytes > 0 {
        ((raw_bytes as f64 - returned_bytes as f64) / raw_bytes as f64) * 100.0
    } else {
        0.0
    };
    let reduction = reduction.max(0.0);

    let truncated =
        redacted_stdout.chars().count() > max_chars || redacted_stderr.chars().count() > max_chars;

    let stats = Stats {
        run_id: Uuid::new_v4().to_string(),
        command: Some(redactor.redact(&command_args.join(" "))),
        exit_code,
        raw_bytes,
        returned_bytes,
        reduction,
        redactions,
        prompt_injection_warnings,
        truncated,
        timeout,
        timestamp: Utc::now().to_rfc3339(),
    };

    Ok(ExecutionResult {
        stdout: final_stdout,
        stderr: final_stderr,
        stored_stdout: redacted_stdout,
        stored_stderr: redacted_stderr,
        stats,
    })
}

fn sanitized_environment(
    environment: &dyn EnvironmentAdapter,
    redactor: &Redactor,
) -> (Vec<(OsString, OsString)>, usize) {
    let mut redactions = 0;
    let env = environment
        .variables()
        .into_iter()
        .map(|(key, value)| {
            if let (Some(key_str), Some(value_str)) = (key.to_str(), value.to_str()) {
                let (sanitized_value, value_redactions) =
                    sanitized_env_value(key_str, value_str, redactor);
                if value_redactions > 0 {
                    redactions += value_redactions;
                    return (key, OsString::from(sanitized_value));
                }
            }

            (key, value)
        })
        .collect();

    (env, redactions)
}

fn sanitized_env_value(key: &str, value: &str, redactor: &Redactor) -> (String, usize) {
    let pair = format!("{key}={value}");
    if !redactor.has_secret(&pair) {
        return (value.to_string(), 0);
    }

    let redacted_pair = redactor.redact(&pair);
    let redactions = Redactor::count_redactions(&pair, &redacted_pair);
    let prefix = format!("{key}=");
    let sanitized_value = redacted_pair
        .strip_prefix(&prefix)
        .unwrap_or(value)
        .to_string();

    (sanitized_value, redactions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_guard::PathAction;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn get_test_lock() -> &'static Mutex<()> {
        TEST_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_execute_simple_command() {
        let _guard = match get_test_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let injector = Injector::new();

        let args = vec!["echo".to_string(), "hello".to_string()];
        let result = execute_command(
            &args,
            &path_guard,
            &redactor,
            &injector,
            Duration::from_secs(5),
            12000,
        );

        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(res.stdout.contains("hello"));
        assert_eq!(res.stats.exit_code, Some(0));
        assert!(!res.stats.timeout);
    }

    #[test]
    fn test_execute_timeout() {
        let _guard = match get_test_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let injector = Injector::new();

        // タイムアウトするはずのコマンド
        let args = vec!["sleep".to_string(), "10".to_string()];
        let result = execute_command(
            &args,
            &path_guard,
            &redactor,
            &injector,
            Duration::from_millis(300),
            12000,
        );

        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(
            res.stats.timeout,
            "Expected timeout to be true, but got res={res:?}"
        );
        assert_eq!(res.stats.exit_code, Some(124));
    }

    #[test]
    fn test_execute_blocked_path() {
        let _guard = match get_test_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let path_guard = PathGuard::new(vec![".env".to_string()], PathAction::Block).unwrap();
        let redactor = Redactor::new();
        let injector = Injector::new();

        // 危険ファイルを引数に指定して実行
        let args = vec!["cat".to_string(), ".env".to_string()];
        let result = execute_command(
            &args,
            &path_guard,
            &redactor,
            &injector,
            Duration::from_secs(5),
            12000,
        );

        // ブロックされた場合はエラーを返す
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn test_execute_redacts_secret_in_command_metadata() {
        let _guard = match get_test_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let injector = Injector::new();

        let args = vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf 'SECRET_KEY=12345'".to_string(),
        ];
        let result = execute_command(
            &args,
            &path_guard,
            &redactor,
            &injector,
            Duration::from_secs(5),
            12000,
        );

        assert!(result.is_ok());
        let res = result.unwrap();
        let command = res.stats.command.unwrap();
        assert!(command.contains("SECRET_KEY=[REDACTED_SECRET]"));
        assert!(!command.contains("12345"));
    }

    #[test]
    fn test_sanitized_env_value_uses_existing_secret_redactor() {
        let redactor = Redactor::new();

        let (value, redactions) = sanitized_env_value("TOKEN", "env_token_13579", &redactor);

        assert_eq!(value, "[REDACTED_SECRET]");
        assert_eq!(redactions, 1);
    }

    #[cfg(unix)]
    #[test]
    fn test_execute_command_uses_injected_environment() {
        let _guard = match get_test_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let environment = crate::platform::TestEnvironment::new("/fixture")
            .with_value("LLM_VEIL_TEST_VALUE", "from-fixture");
        let process = SystemProcessAdapter;
        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let injector = Injector::new();
        let args = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf '%s' \"$LLM_VEIL_TEST_VALUE\"".to_string(),
        ];

        let result = execute_command_with_adapters(
            &args,
            &path_guard,
            &redactor,
            &injector,
            Duration::from_secs(5),
            12000,
            &environment,
            &process,
        )
        .unwrap();

        assert_eq!(result.stdout, "from-fixture");
    }

    #[test]
    fn test_execute_truncates_stdout_and_stderr_with_configured_limit() {
        let _guard = match get_test_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let injector = Injector::new();

        let args = vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf 'abcdefghijkl'; printf 'mnopqrstuvwx' >&2".to_string(),
        ];
        let result = execute_command(
            &args,
            &path_guard,
            &redactor,
            &injector,
            Duration::from_secs(5),
            8,
        );

        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(res.stdout.contains("[TRUNCATED: omitted 4 bytes]"));
        assert!(res.stderr.contains("[TRUNCATED: omitted 4 bytes]"));
        assert!(res.stats.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn test_execute_sanitizes_buffered_output_after_sigterm() {
        let _guard = match get_test_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let injector = Injector::new();
        let signaler = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(300));
            crate::platform::raise_signal_for_test(libc::SIGTERM);
        });

        let args = vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf 'SECRET_KEY=interrupt_token_97531\\n'; sleep 5".to_string(),
        ];
        let result = execute_command(
            &args,
            &path_guard,
            &redactor,
            &injector,
            Duration::from_secs(5),
            12000,
        );

        signaler.join().unwrap();

        // Allow time for asynchronous signal delivery to fully settle in OS
        std::thread::sleep(Duration::from_millis(150));
        reset_received_signal();

        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.stats.exit_code, Some(128 + libc::SIGTERM));
        assert!(res.stdout.contains("SECRET_KEY=[REDACTED_SECRET]"));
        assert!(!res.stdout.contains("interrupt_token_97531"));
    }
}
