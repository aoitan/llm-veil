use chrono::Utc;
use clap::Parser;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

mod cli;
mod config;
mod executor;
mod injector;
mod path_guard;
mod redactor;
mod stats;
mod truncator;
mod utils;

use config::PromptInjectionAction;
use injector::Injector;
use path_guard::{PathAction, PathGuard};
use redactor::Redactor;
use stats::Stats;

struct FilteredOutput {
    content: String,
    redactions: usize,
}

const CAT_SECRET_BLOCKED_ERROR: &str = "File contains secret patterns and was blocked";
const CAT_PROMPT_INJECTION_BLOCKED_ERROR: &str =
    "File contains prompt-injection patterns and was blocked";

fn final_output_filter(content: &str, redactor: &Redactor) -> FilteredOutput {
    let redacted = redactor.redact(content);
    let redactions = Redactor::count_redactions(content, &redacted);

    FilteredOutput {
        content: redacted,
        redactions,
    }
}

fn blocked_cat_output(reason: &str, path_rule: &str, redactions: usize) -> String {
    format!(
        "blocked: true\nreason: {}\npath_rule: {}\nredactions: {}\nexit_code: 1",
        reason, path_rule, redactions
    )
}

fn sanitized_blocked_cat_output(
    reason: &str,
    path_rule: &str,
    redactions: usize,
    redactor: &Redactor,
) -> String {
    let status = blocked_cat_output(reason, path_rule, redactions);
    final_output_filter(&status, redactor).content
}

fn main() {
    let mut config = config::load_config();
    let cli = cli::Cli::parse();

    // コマンドライン引数による上書き
    if let Some(action_str) = &cli.action {
        config.action = match action_str.as_str() {
            "block" => PathAction::Block,
            "redact" => PathAction::Redact,
            "allow" => PathAction::Allow,
            _ => config.action,
        };
    }
    if let Some(timeout) = cli.timeout {
        config.timeout_seconds = timeout;
    }
    if let Some(max_chars) = cli.max_chars {
        config.max_chars = max_chars;
    }

    let path_guard = match PathGuard::new(config.blocked_patterns.clone(), config.action) {
        Ok(pg) => pg,
        Err(e) => {
            eprintln!("Error: Invalid pattern in configuration: {}", e);
            std::process::exit(1);
        }
    };
    let redactor = Redactor::new();
    let injector = Injector::new();

    match cli.command {
        cli::Commands::Cat { file } => {
            if let Err(e) = handle_cat(&file, &path_guard, &redactor, &injector, &config) {
                if e.kind() == io::ErrorKind::PermissionDenied
                    && (e.to_string() == CAT_SECRET_BLOCKED_ERROR
                        || e.to_string() == CAT_PROMPT_INJECTION_BLOCKED_ERROR)
                {
                    std::process::exit(1);
                }
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        cli::Commands::Grep { pattern, path } => {
            let path_val = path.unwrap_or_else(|| ".".to_string());
            if let Err(e) = handle_grep(
                &pattern,
                &path_val,
                &path_guard,
                &redactor,
                &injector,
                &config,
            ) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        cli::Commands::Run {
            report_json,
            command,
        } => {
            if let Err(e) = handle_run(
                &command,
                report_json.as_deref(),
                &path_guard,
                &redactor,
                &injector,
                &config,
            ) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        cli::Commands::Report { run_id } => {
            if let Err(e) = handle_report(run_id.as_deref()) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn handle_cat(
    file_path: &str,
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    config: &config::Config,
) -> io::Result<()> {
    // 危険パスのブロック
    if let Some(path_rule) = path_guard.block_rule(file_path) {
        let status = sanitized_blocked_cat_output("path_blocked", path_rule, 0, redactor);
        let final_output = utils::wrap_untrusted(&status);

        println!("{}", final_output);

        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Access to blocked path was denied",
        ));
    }

    // ファイル読み込み
    let bytes = fs::read(file_path)?;
    let content = String::from_utf8_lossy(&bytes).into_owned();

    // シークレット候補があれば原則BLOCK
    if redactor.has_secret(&content) {
        let redacted = redactor.redact(&content);
        let redactions = Redactor::count_redactions(&content, &redacted);
        let status = sanitized_blocked_cat_output("secret_detected", "", redactions, redactor);
        let warnings = injector.detect_injection(&redacted);
        let final_output = utils::wrap_untrusted(&status);

        println!("{}", final_output);

        let raw_bytes = bytes.len();
        let returned_bytes = final_output.len();
        let reduction = if raw_bytes > 0 {
            ((raw_bytes as f64 - returned_bytes as f64) / raw_bytes as f64) * 100.0
        } else {
            0.0
        };

        let stats = Stats {
            run_id: Uuid::new_v4().to_string(),
            command: Some(redactor.redact(&format!("cat {}", file_path))),
            exit_code: Some(1),
            raw_bytes,
            returned_bytes,
            reduction: reduction.max(0.0),
            redactions,
            prompt_injection_warnings: warnings,
            truncated: false,
            timeout: false,
            timestamp: Utc::now().to_rfc3339(),
        };

        stats::save_stats(&stats)?;
        print_stats_to_stderr(&stats);

        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            CAT_SECRET_BLOCKED_ERROR,
        ));
    }

    let redacted_for_scan = redactor.redact(&content);
    let scan_redactions = Redactor::count_redactions(&content, &redacted_for_scan);
    let warnings = injector.detect_injection(&redacted_for_scan);
    if warnings > 0 && config.prompt_injection_action == PromptInjectionAction::Block {
        let status = sanitized_blocked_cat_output(
            "prompt_injection_detected",
            "",
            scan_redactions,
            redactor,
        );
        let final_output = utils::wrap_untrusted(&status);

        println!("{}", final_output);

        let raw_bytes = bytes.len();
        let returned_bytes = final_output.len();
        let reduction = if raw_bytes > 0 {
            ((raw_bytes as f64 - returned_bytes as f64) / raw_bytes as f64) * 100.0
        } else {
            0.0
        };

        let stats = Stats {
            run_id: Uuid::new_v4().to_string(),
            command: Some(redactor.redact(&format!("cat {}", file_path))),
            exit_code: Some(1),
            raw_bytes,
            returned_bytes,
            reduction: reduction.max(0.0),
            redactions: scan_redactions,
            prompt_injection_warnings: warnings,
            truncated: false,
            timeout: false,
            timestamp: Utc::now().to_rfc3339(),
        };

        stats::save_stats(&stats)?;
        print_stats_to_stderr(&stats);

        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            CAT_PROMPT_INJECTION_BLOCKED_ERROR,
        ));
    }

    // サニタイズの適用
    let redacted = if path_guard.should_redact(file_path) {
        redactor.redact(&content)
    } else {
        content
    };

    let truncated = truncator::truncate(&redacted, config.max_chars);
    let truncated_flag = redacted.chars().count() > config.max_chars;
    let filtered = final_output_filter(&truncated, redactor);

    // インジェクション警告
    let warnings = injector.detect_injection(&filtered.content);
    if warnings > 0 {
        eprintln!("WARNING: possible prompt-injection text detected.");
    }

    // AI向け宣言
    let final_output = utils::wrap_untrusted(&filtered.content);

    // 出力
    println!("{}", final_output);

    // stats記録
    let raw_bytes = bytes.len();
    let returned_bytes = final_output.len();
    let reduction = if raw_bytes > 0 {
        ((raw_bytes as f64 - returned_bytes as f64) / raw_bytes as f64) * 100.0
    } else {
        0.0
    };
    let reduction = reduction.max(0.0);

    let stats = Stats {
        run_id: Uuid::new_v4().to_string(),
        command: Some(redactor.redact(&format!("cat {}", file_path))),
        exit_code: Some(0),
        raw_bytes,
        returned_bytes,
        reduction,
        redactions: filtered.redactions,
        prompt_injection_warnings: warnings,
        truncated: truncated_flag,
        timeout: false,
        timestamp: Utc::now().to_rfc3339(),
    };

    stats::save_stats(&stats)?;
    print_stats_to_stderr(&stats);

    Ok(())
}

fn handle_grep(
    pattern: &str,
    target_path: &str,
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    _config: &config::Config,
) -> io::Result<()> {
    let mut results = Vec::new();
    let mut grep_redactions = 0;
    let path = Path::new(target_path);

    if path.is_dir() {
        visit_dirs(
            path,
            pattern,
            path_guard,
            redactor,
            &mut results,
            &mut grep_redactions,
        )?;
    } else {
        let path_str = path.to_string_lossy();
        if !path_guard.should_block(&path_str) {
            grep_file(
                path,
                pattern,
                path_guard,
                redactor,
                &mut results,
                &mut grep_redactions,
            )?;
        }
    }

    let raw_results = results.join("\n");
    let raw_bytes = raw_results.len();

    // 行数制限（最大200行）での中間カット
    let max_lines = 200;
    let (truncated_lines, _omitted_bytes) = truncate_lines(&results, max_lines);
    let truncated_flag = results.len() > max_lines;
    let filtered = final_output_filter(&truncated_lines, redactor);

    // インジェクション警告
    let warnings = injector.detect_injection(&filtered.content);
    if warnings > 0 {
        eprintln!("WARNING: possible prompt-injection text detected.");
    }

    // AI向け宣言
    let final_output = utils::wrap_untrusted(&filtered.content);

    // 出力
    println!("{}", final_output);

    // stats記録
    let returned_bytes = final_output.len();
    let reduction = if raw_bytes > 0 {
        ((raw_bytes as f64 - returned_bytes as f64) / raw_bytes as f64) * 100.0
    } else {
        0.0
    };
    let reduction = reduction.max(0.0);

    let stats = Stats {
        run_id: Uuid::new_v4().to_string(),
        command: Some(redactor.redact(&format!("grep {} {}", pattern, target_path))),
        exit_code: Some(0),
        raw_bytes,
        returned_bytes,
        reduction,
        redactions: grep_redactions + filtered.redactions,
        prompt_injection_warnings: warnings,
        truncated: truncated_flag,
        timeout: false,
        timestamp: Utc::now().to_rfc3339(),
    };

    stats::save_stats(&stats)?;
    print_stats_to_stderr(&stats);

    Ok(())
}

fn visit_dirs(
    dir: &Path,
    pattern: &str,
    path_guard: &PathGuard,
    redactor: &Redactor,
    results: &mut Vec<String>,
    redactions: &mut usize,
) -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let path_str = path.to_string_lossy();

            if path_guard.should_block(&path_str) {
                continue;
            }

            if path.is_dir() {
                visit_dirs(&path, pattern, path_guard, redactor, results, redactions)?;
            } else {
                grep_file(&path, pattern, path_guard, redactor, results, redactions)?;
            }
        }
    }
    Ok(())
}

fn grep_file(
    path: &Path,
    pattern: &str,
    _path_guard: &PathGuard,
    redactor: &Redactor,
    results: &mut Vec<String>,
    redactions: &mut usize,
) -> io::Result<()> {
    let path_str = path.to_string_lossy().into_owned();
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);

    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue, // バイナリなどの読み込みエラーはスキップ
        };

        if line.contains(pattern) {
            let processed_line = redactor.redact(&line);
            *redactions += Redactor::count_redactions(&line, &processed_line);
            results.push(format!("{}:{}:{}", path_str, line_num + 1, processed_line));
        }
    }
    Ok(())
}

fn truncate_lines(lines: &[String], max_lines: usize) -> (String, usize) {
    let total_lines = lines.len();
    if total_lines <= max_lines {
        return (lines.join("\n"), 0);
    }

    let half = max_lines / 2;
    let prefix = &lines[0..half];
    let suffix = &lines[total_lines - (max_lines - half)..total_lines];

    let omitted_lines = total_lines - max_lines;
    let mut omitted_bytes = 0;
    for line in &lines[half..total_lines - (max_lines - half)] {
        omitted_bytes += line.len() + 1;
    }

    let output = format!(
        "{}\n... [TRUNCATED: omitted {} lines ({} bytes)] ...\n{}",
        prefix.join("\n"),
        omitted_lines,
        omitted_bytes,
        suffix.join("\n")
    );
    (output, omitted_bytes)
}

fn handle_run(
    command_args: &[String],
    report_json: Option<&str>,
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    config: &config::Config,
) -> io::Result<()> {
    let timeout_dur = Duration::from_secs(config.timeout_seconds);
    let res = executor::execute_command(
        command_args,
        path_guard,
        redactor,
        injector,
        timeout_dur,
        config.max_chars,
    )?;

    let filtered_stdout = final_output_filter(&res.stdout, redactor);
    let filtered_stderr = final_output_filter(&res.stderr, redactor);

    // AI向け宣言でラップ
    let final_stdout = utils::wrap_untrusted(&filtered_stdout.content);

    // 出力
    println!("{}", final_stdout);
    eprintln!("{}", filtered_stderr.content);

    // インジェクション警告の検出確認
    if res.stats.prompt_injection_warnings > 0 {
        eprintln!("WARNING: possible prompt-injection text detected.");
    }

    // stats記録と表示
    let mut stats = res.stats.clone();
    stats.redactions += filtered_stdout.redactions + filtered_stderr.redactions;
    stats.returned_bytes = final_stdout.len() + filtered_stderr.content.len();
    let raw_bytes = stats.raw_bytes;
    stats.reduction = if raw_bytes > 0 {
        ((raw_bytes as f64 - stats.returned_bytes as f64) / raw_bytes as f64) * 100.0
    } else {
        0.0
    };
    stats.reduction = stats.reduction.max(0.0);

    stats::save_stats(&stats)?;
    if let Some(path) = report_json {
        write_stats_json(path, &stats)?;
    }
    print_stats_to_stderr(&stats);

    if let Some(code) = res.stats.exit_code {
        std::process::exit(code);
    } else {
        std::process::exit(0);
    }
}

fn handle_report(run_id: Option<&str>) -> io::Result<()> {
    let stats = if let Some(id) = run_id {
        stats::load_stats(id)?
    } else {
        stats::load_last_stats()?
    };
    let redactor = Redactor::new();
    let output = format_report_output(&stats, &redactor);

    print!("{}", output);

    Ok(())
}

fn write_stats_json(path: &str, stats: &Stats) -> io::Result<()> {
    let json = stats::sanitized_stats_json(stats)?;
    fs::write(path, json)?;
    Ok(())
}

fn format_report_output(stats: &Stats, redactor: &Redactor) -> String {
    let command = stats
        .command
        .as_deref()
        .map(|command| command.to_string())
        .unwrap_or_else(|| "-".to_string());

    let output = format!(
        "command: {}\nexit_code: {}\nraw_bytes: {}\nreturned_bytes: {}\nreduction: {:.1}%\nredactions: {}\nprompt_injection_warnings: {}\ntruncated: {}\ntimeout: {}\n",
        command,
        stats
            .exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string()),
        stats.raw_bytes,
        stats.returned_bytes,
        stats.reduction,
        stats.redactions,
        stats.prompt_injection_warnings,
        stats.truncated,
        stats.timeout
    );

    final_output_filter(&output, redactor).content
}

fn print_stats_to_stderr(stats: &Stats) {
    let redactor = Redactor::new();
    eprint!("{}", format_stats_for_stderr(stats, &redactor));
}

fn format_stats_for_stderr(stats: &Stats, redactor: &Redactor) -> String {
    let mut output = String::new();

    output.push_str("\n[llm-veil stats]\n");
    output.push_str(&format!("run_id: {}\n", stats.run_id));
    if let Some(cmd) = &stats.command {
        output.push_str(&format!("command: {}\n", redactor.redact(cmd)));
    }
    if let Some(code) = stats.exit_code {
        output.push_str(&format!("exit_code: {}\n", code));
    }
    output.push_str(&format!("raw_bytes: {}\n", stats.raw_bytes));
    output.push_str(&format!("returned_bytes: {}\n", stats.returned_bytes));
    output.push_str(&format!("reduction: {:.1}%\n", stats.reduction));
    output.push_str(&format!("redactions: {}\n", stats.redactions));
    output.push_str(&format!(
        "prompt_injection_warnings: {}\n",
        stats.prompt_injection_warnings
    ));
    output.push_str(&format!("truncated: {}\n", stats.truncated));
    output.push_str(&format!("timeout: {}\n", stats.timeout));

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_grep_file_redacts_secret_on_allowed_path() {
        let file_path = std::env::temp_dir().join(format!("llm-veil-grep-{}.txt", Uuid::new_v4()));
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "const token = \"my_jwt_token\";").unwrap();

        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let mut results = Vec::new();
        let mut redactions = 0;

        grep_file(
            &file_path,
            "token",
            &path_guard,
            &redactor,
            &mut results,
            &mut redactions,
        )
        .unwrap();
        fs::remove_file(&file_path).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(redactions, 1);
        assert!(results[0].contains("const token = \"[REDACTED_SECRET]\";"));
        assert!(!results[0].contains("my_jwt_token"));
    }

    #[test]
    fn test_handle_cat_blocks_secrets() {
        let file_path = std::env::temp_dir().join(format!("llm-veil-cat-{}.txt", Uuid::new_v4()));
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "export API_KEY=AIzaSyAThisIsAFakeApiKeyForTesting").unwrap();

        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let injector = Injector::new();
        let config = config::Config {
            action: PathAction::Allow,
            prompt_injection_action: PromptInjectionAction::Block,
            timeout_seconds: 10,
            max_chars: 1000,
            blocked_patterns: vec![],
        };

        let res = handle_cat(
            file_path.to_str().unwrap(),
            &path_guard,
            &redactor,
            &injector,
            &config,
        );
        fs::remove_file(&file_path).unwrap();

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), CAT_SECRET_BLOCKED_ERROR);
    }

    #[test]
    fn test_stats_stderr_formatter_redacts_command() {
        let redactor = Redactor::new();
        let stats = Stats {
            run_id: Uuid::new_v4().to_string(),
            command: Some("sh -c 'printf SECRET_KEY=12345'".to_string()),
            exit_code: Some(0),
            raw_bytes: 16,
            returned_bytes: 16,
            reduction: 0.0,
            redactions: 0,
            prompt_injection_warnings: 0,
            truncated: false,
            timeout: false,
            timestamp: Utc::now().to_rfc3339(),
        };

        let output = format_stats_for_stderr(&stats, &redactor);

        assert!(output.contains("SECRET_KEY=[REDACTED_SECRET]"));
        assert!(!output.contains("12345"));
    }

    #[test]
    fn test_report_formatter_applies_final_redactor_to_whole_output() {
        let redactor = Redactor::new();
        let stats = Stats {
            run_id: Uuid::new_v4().to_string(),
            command: Some("sh -c 'printf SECRET_KEY=12345'".to_string()),
            exit_code: Some(0),
            raw_bytes: 16,
            returned_bytes: 16,
            reduction: 0.0,
            redactions: 0,
            prompt_injection_warnings: 0,
            truncated: false,
            timeout: false,
            timestamp: Utc::now().to_rfc3339(),
        };

        let output = format_report_output(&stats, &redactor);

        assert!(output.contains("SECRET_KEY=[REDACTED_SECRET]"));
        assert!(!output.contains("12345"));
    }

    #[test]
    fn test_blocked_cat_contract_output_redacts_path_rule() {
        let redactor = Redactor::new();
        let output =
            sanitized_blocked_cat_output("path_blocked", "/Users/alice/.ssh/*", 0, &redactor);

        assert!(output.contains("blocked: true"));
        assert!(output.contains("reason: path_blocked"));
        assert!(output.contains("path_rule: [REDACTED_PATH]/.ssh/*"));
        assert!(!output.contains("/Users/alice"));
    }
}
