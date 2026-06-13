use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::time::Duration;
use clap::Parser;
use uuid::Uuid;
use chrono::Utc;

mod path_guard;
mod redactor;
mod truncator;
mod injector;
mod stats;
mod executor;
mod config;
mod utils;
mod cli;

use path_guard::{PathAction, PathGuard};
use redactor::Redactor;
use injector::Injector;
use stats::Stats;

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

    let path_guard = PathGuard::new(config.blocked_patterns.clone(), config.action);
    let redactor = Redactor::new();
    let injector = Injector::new();

    match cli.command {
        cli::Commands::Cat { file } => {
            if let Err(e) = handle_cat(&file, &path_guard, &redactor, &injector, &config) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        cli::Commands::Grep { pattern, path } => {
            let path_val = path.unwrap_or_else(|| ".".to_string());
            if let Err(e) = handle_grep(&pattern, &path_val, &path_guard, &redactor, &injector, &config) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        cli::Commands::Run { command } => {
            if let Err(e) = handle_run(&command, &path_guard, &redactor, &injector, &config) {
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
    if path_guard.should_block(file_path) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Access to blocked path was denied"));
    }

    // ファイル読み込み
    let bytes = fs::read(file_path)?;
    let content = String::from_utf8_lossy(&bytes).into_owned();

    // シークレット候補があれば原則BLOCK
    if redactor.has_secret(&content) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "File contains secret patterns and was blocked"));
    }

    // サニタイズの適用
    let redacted = if path_guard.should_redact(file_path) {
        redactor.redact(&content)
    } else {
        content
    };

    // インジェクション警告
    let warnings = injector.detect_injection(&redacted);
    if warnings > 0 {
        eprintln!("WARNING: possible prompt-injection text detected.");
    }

    // 中間カット
    let truncated = truncator::truncate(&redacted, config.max_chars);
    let truncated_flag = redacted.chars().count() > config.max_chars;

    // AI向け宣言
    let final_output = utils::wrap_untrusted(&truncated);

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
        command: Some(format!("cat {}", file_path)),
        exit_code: Some(0),
        raw_bytes,
        returned_bytes,
        reduction,
        redactions: 0,
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
    let path = Path::new(target_path);

    if path.is_dir() {
        visit_dirs(path, pattern, path_guard, redactor, &mut results)?;
    } else {
        let path_str = path.to_string_lossy();
        if !path_guard.should_block(&path_str) {
            grep_file(path, pattern, path_guard, redactor, &mut results)?;
        }
    }

    let raw_results = results.join("\n");
    let raw_bytes = raw_results.len();

    // 行数制限（最大200行）での中間カット
    let max_lines = 200;
    let (truncated_lines, _omitted_bytes) = truncate_lines(&results, max_lines);
    let truncated_flag = results.len() > max_lines;

    // インジェクション警告
    let warnings = injector.detect_injection(&truncated_lines);
    if warnings > 0 {
        eprintln!("WARNING: possible prompt-injection text detected.");
    }

    // AI向け宣言
    let final_output = utils::wrap_untrusted(&truncated_lines);

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
        command: Some(format!("grep {} {}", pattern, target_path)),
        exit_code: Some(0),
        raw_bytes,
        returned_bytes,
        reduction,
        redactions: 0, // grep_file 内で個別にカウントしていないため簡易的に0
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
                visit_dirs(&path, pattern, path_guard, redactor, results)?;
            } else {
                grep_file(&path, pattern, path_guard, redactor, results)?;
            }
        }
    }
    Ok(())
}

fn grep_file(
    path: &Path,
    pattern: &str,
    path_guard: &PathGuard,
    redactor: &Redactor,
    results: &mut Vec<String>,
) -> io::Result<()> {
    let path_str = path.to_string_lossy().into_owned();
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);

    let should_redact = path_guard.should_redact(&path_str);

    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue, // バイナリなどの読み込みエラーはスキップ
        };

        if line.contains(pattern) {
            let processed_line = if should_redact {
                redactor.redact(&line)
            } else {
                line
            };
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
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    config: &config::Config,
) -> io::Result<()> {
    let timeout_dur = Duration::from_secs(config.timeout_seconds);
    let res = executor::execute_command(command_args, path_guard, redactor, injector, timeout_dur)?;

    // AI向け宣言でラップ
    let final_stdout = utils::wrap_untrusted(&res.stdout);

    // 出力
    println!("{}", final_stdout);
    eprintln!("{}", res.stderr);

    // インジェクション警告の検出確認
    if res.stats.prompt_injection_warnings > 0 {
        eprintln!("WARNING: possible prompt-injection text detected.");
    }

    // stats記録と表示
    let mut stats = res.stats.clone();
    stats.returned_bytes = final_stdout.len() + res.stderr.len();
    let raw_bytes = stats.raw_bytes;
    stats.reduction = if raw_bytes > 0 {
        ((raw_bytes as f64 - stats.returned_bytes as f64) / raw_bytes as f64) * 100.0
    } else {
        0.0
    };
    stats.reduction = stats.reduction.max(0.0);

    stats::save_stats(&stats)?;
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

    println!("command: {}", stats.command.unwrap_or_else(|| "-".to_string()));
    println!("exit_code: {}", stats.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string()));
    println!("raw_bytes: {}", stats.raw_bytes);
    println!("returned_bytes: {}", stats.returned_bytes);
    println!("reduction: {:.1}%", stats.reduction);
    println!("redactions: {}", stats.redactions);
    println!("prompt_injection_warnings: {}", stats.prompt_injection_warnings);
    println!("truncated: {}", stats.truncated);
    println!("timeout: {}", stats.timeout);

    Ok(())
}

fn print_stats_to_stderr(stats: &Stats) {
    eprintln!("\n[llm-veil stats]");
    eprintln!("run_id: {}", stats.run_id);
    if let Some(cmd) = &stats.command {
        eprintln!("command: {}", cmd);
    }
    if let Some(code) = stats.exit_code {
        eprintln!("exit_code: {}", code);
    }
    eprintln!("raw_bytes: {}", stats.raw_bytes);
    eprintln!("returned_bytes: {}", stats.returned_bytes);
    eprintln!("reduction: {:.1}%", stats.reduction);
    eprintln!("redactions: {}", stats.redactions);
    eprintln!("prompt_injection_warnings: {}", stats.prompt_injection_warnings);
    eprintln!("truncated: {}", stats.truncated);
    eprintln!("timeout: {}", stats.timeout);
}
