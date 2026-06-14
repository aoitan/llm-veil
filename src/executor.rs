use crate::injector::Injector;
use crate::path_guard::PathGuard;
use crate::redactor::Redactor;
use crate::stats::Stats;
use crate::truncator::truncate;
use chrono::Utc;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::time::Duration;
use uuid::Uuid;
use wait_timeout::ChildExt;

#[derive(Debug)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub stats: Stats,
}

pub fn execute_command(
    command_args: &[String],
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    timeout_duration: Duration,
    max_chars: usize,
) -> Result<ExecutionResult, io::Error> {
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

    let mut cmd = Command::new(&command_args[0]);
    cmd.args(&command_args[1..]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    let mut timeout = false;
    let mut exit_code = None;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();

    match child.wait_timeout(timeout_duration)? {
        Some(status) => {
            exit_code = status.code();
            // 出力の読み出し
            if let Some(mut stdout) = child.stdout.take() {
                stdout.read_to_end(&mut stdout_bytes)?;
            }
            if let Some(mut stderr) = child.stderr.take() {
                stderr.read_to_end(&mut stderr_bytes)?;
            }
        }
        None => {
            timeout = true;
            child.kill()?;
            let _ = child.wait(); // ゾンビプロセス化を防ぐ
        }
    }

    let raw_stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let raw_stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

    // Redact (置換) の適用
    let redacted_stdout = redactor.redact(&raw_stdout);
    let redacted_stderr = redactor.redact(&raw_stderr);

    let redactions = Redactor::count_redactions(&raw_stdout, &redacted_stdout)
        + Redactor::count_redactions(&raw_stderr, &redacted_stderr);

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
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_guard::PathAction;
    use std::time::Duration;

    #[test]
    fn test_execute_simple_command() {
        let path_guard = PathGuard::new(vec![], PathAction::Allow);
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
        let path_guard = PathGuard::new(vec![], PathAction::Allow);
        let redactor = Redactor::new();
        let injector = Injector::new();

        // タイムアウトするはずのコマンド
        let args = vec!["sleep".to_string(), "10".to_string()];
        let result = execute_command(
            &args,
            &path_guard,
            &redactor,
            &injector,
            Duration::from_millis(100),
            12000,
        );

        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(res.stats.timeout);
    }

    #[test]
    fn test_execute_blocked_path() {
        let path_guard = PathGuard::new(vec![".env".to_string()], PathAction::Block);
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
        let path_guard = PathGuard::new(vec![], PathAction::Allow);
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
    fn test_execute_truncates_stdout_and_stderr_with_configured_limit() {
        let path_guard = PathGuard::new(vec![], PathAction::Allow);
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
}
