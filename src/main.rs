#![deny(unsafe_code)]
#![deny(unfulfilled_lint_expectations)]
#![warn(unreachable_pub)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::too_many_arguments)]

use chrono::Utc;
use clap::Parser;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

mod cli;
mod config;
mod executor;
mod injector;
mod output;
mod path_guard;
mod path_io;
mod persistence;
mod platform;
mod redactor;
mod safety;
mod stats;
mod storage;
mod truncator;
mod utils;

use config::PromptInjectionAction;
use injector::Injector;
use output::{OutputRouter, StdOutputAdapter};
use path_guard::{PathAction, PathGuard};
use path_io::{GrepOutcome, PathBoundaryError, PathIo, TraversalCompleteness, WorkspaceResolver};
use persistence::Persistence;
use platform::{EnvironmentAdapter, ProcessAdapter, SystemEnvironment, SystemProcessAdapter};
use redactor::Redactor;
use safety::SanitizedStoredContent;
use stats::Stats;
use storage::{DeleteStatus, LookupStatus, RunStore, StorageReceipt, Stream};

struct FilteredOutput {
    content: String,
    redactions: usize,
}

const CAT_SECRET_BLOCKED_ERROR: &str = "File contains secret patterns and was blocked";
const CAT_PROMPT_INJECTION_BLOCKED_ERROR: &str =
    "File contains prompt-injection patterns and was blocked";
const RUN_PATH_BLOCKED_ERROR: &str = "Command arguments contain a blocked path";
const RUN_PROMPT_INJECTION_BLOCKED_ERROR: &str =
    "Command output contains prompt-injection patterns and was blocked";
const WORKSPACE_BOUNDARY_RULE: &str = "workspace_boundary";
const GREP_PARTIAL_ERROR: &str = "grep traversal was incomplete; results may be partial";
const GREP_PROMPT_INJECTION_BLOCKED_ERROR: &str =
    "grep output contains prompt-injection patterns and was blocked";

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
        "blocked: true\nreason: {reason}\npath_rule: {path_rule}\nredactions: {redactions}\nexit_code: 1"
    )
}

#[cfg(test)]
fn sanitized_blocked_cat_output(
    reason: &str,
    path_rule: &str,
    redactions: usize,
    redactor: &Redactor,
) -> String {
    let status = blocked_cat_output(reason, path_rule, redactions);
    final_output_filter(&status, redactor).content
}

#[cfg(test)]
fn format_error_for_stderr(message: &str, redactor: &Redactor) -> String {
    final_output_filter(&format!("Error: {message}"), redactor).content
}

fn emit_error(output: &mut OutputRouter<'_>, message: &str) {
    let _ = output.emit_stderr_prepared(
        &format!("Error: {message}"),
        PromptInjectionAction::Warn,
        false,
    );
}

fn main() {
    let environment = SystemEnvironment;
    let process = SystemProcessAdapter;
    let mut config = config::load_config(&environment);
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

    let redactor = Redactor::new_with_environment(&environment);
    let injector = Injector::new();
    let mut std_output = StdOutputAdapter;
    let mut output = OutputRouter::new(
        &mut std_output,
        &redactor,
        &injector,
        config.prompt_injection_action,
        config.max_chars,
    );
    let path_guard = match PathGuard::new(config.blocked_patterns.clone(), config.action) {
        Ok(pg) => pg,
        Err(e) => {
            emit_error(
                &mut output,
                &format!("Invalid pattern in configuration: {e}"),
            );
            std::process::exit(1);
        }
    };

    match cli.command {
        cli::Commands::Cat { no_store, file } => {
            let mut persistence = Persistence::new_with_environment(no_store, &environment);
            if let Err(e) = handle_cat(
                &file,
                &path_guard,
                &redactor,
                &injector,
                &config,
                &environment,
                &mut output,
                &mut persistence,
            ) {
                if e.kind() == io::ErrorKind::PermissionDenied
                    && (e.to_string() == CAT_SECRET_BLOCKED_ERROR
                        || e.to_string() == CAT_PROMPT_INJECTION_BLOCKED_ERROR)
                {
                    std::process::exit(1);
                }
                emit_error(&mut output, &e.to_string());
                std::process::exit(1);
            }
        }
        cli::Commands::Grep {
            no_store,
            pattern,
            path,
        } => {
            let path_val = path.unwrap_or_else(|| ".".to_string());
            let mut persistence = Persistence::new_with_environment(no_store, &environment);
            if let Err(e) = handle_grep(
                &pattern,
                &path_val,
                &path_guard,
                &redactor,
                &injector,
                &config,
                &environment,
                &mut output,
                &mut persistence,
            ) {
                if e.kind() == io::ErrorKind::PermissionDenied
                    && e.to_string() == GREP_PROMPT_INJECTION_BLOCKED_ERROR
                {
                    std::process::exit(1);
                }
                emit_error(&mut output, &e.to_string());
                let exit_code = if e.to_string() == GREP_PARTIAL_ERROR {
                    2
                } else {
                    1
                };
                std::process::exit(exit_code);
            }
        }
        cli::Commands::Run {
            report_json,
            no_store,
            command,
        } => {
            let mut persistence = Persistence::new_with_environment(no_store, &environment);
            if let Err(e) = handle_run(
                &command,
                report_json.as_deref(),
                &path_guard,
                &redactor,
                &injector,
                &config,
                &environment,
                &process,
                &mut output,
                &mut persistence,
            ) {
                if e.kind() == io::ErrorKind::PermissionDenied
                    && (e.to_string() == RUN_PATH_BLOCKED_ERROR
                        || e.to_string() == RUN_PROMPT_INJECTION_BLOCKED_ERROR)
                {
                    std::process::exit(1);
                }
                emit_error(&mut output, &e.to_string());
                std::process::exit(1);
            }
        }
        cli::Commands::Report { run_id } => {
            if let Err(e) = handle_report(run_id.as_deref(), &redactor, &environment, &mut output) {
                emit_error(&mut output, &e.to_string());
                std::process::exit(1);
            }
        }
        cli::Commands::Retrieve {
            run_id,
            stream,
            start_line,
            lines,
        } => {
            if let Err(e) = handle_retrieve(
                &run_id,
                &stream,
                start_line,
                lines,
                &redactor,
                &injector,
                &config,
                &environment,
                &mut output,
            ) {
                emit_error(&mut output, &e.to_string());
                std::process::exit(1);
            }
        }
        cli::Commands::Search {
            run_id,
            stream,
            literal,
            cursor,
        } => {
            if let Err(e) = handle_search(
                &run_id,
                &stream,
                &literal,
                cursor.as_deref(),
                &redactor,
                &injector,
                &config,
                &environment,
                &mut output,
            ) {
                emit_error(&mut output, &e.to_string());
                std::process::exit(1);
            }
        }
        cli::Commands::Store { command } => {
            if let Err(e) = handle_store(command, &environment, &mut output) {
                emit_error(&mut output, &e.to_string());
                std::process::exit(1);
            }
        }
    }
}

fn path_boundary_to_io(error: PathBoundaryError) -> io::Error {
    let kind = match &error {
        PathBoundaryError::WorkspaceRoot(error)
        | PathBoundaryError::NotFound(error)
        | PathBoundaryError::Io(error) => error.kind(),
        PathBoundaryError::PolicyDenied { .. }
        | PathBoundaryError::OutsideWorkspace
        | PathBoundaryError::SymlinkNotAllowed => io::ErrorKind::PermissionDenied,
        PathBoundaryError::WrongTargetKind { .. } | PathBoundaryError::UnsupportedFileType => {
            io::ErrorKind::InvalidInput
        }
    };
    io::Error::new(kind, error)
}

fn cat_path_boundary_rejection(
    error: &PathBoundaryError,
    output: &mut OutputRouter<'_>,
) -> io::Result<Option<io::Error>> {
    let (path_rule, message) = if let Some(rule) = error.policy_rule() {
        (rule, "Access to blocked path was denied")
    } else if error.is_workspace_boundary() {
        (
            WORKSPACE_BOUNDARY_RULE,
            "Access outside workspace was denied",
        )
    } else if matches!(error, PathBoundaryError::SymlinkNotAllowed) {
        (
            WORKSPACE_BOUNDARY_RULE,
            "Access through symbolic link was denied",
        )
    } else {
        return Ok(None);
    };

    let status = blocked_cat_output("path_blocked", path_rule, 0);
    output.emit_stdout_prepared(&status, PromptInjectionAction::Warn, false)?;
    Ok(Some(io::Error::new(
        io::ErrorKind::PermissionDenied,
        message,
    )))
}

#[expect(
    clippy::too_many_arguments,
    reason = "WB-15-001: retain the migrated cat boundary until the application context refactor"
)]
fn handle_cat(
    file_path: &str,
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    config: &config::Config,
    environment: &dyn EnvironmentAdapter,
    output: &mut OutputRouter<'_>,
    persistence: &mut Persistence,
) -> io::Result<()> {
    let workspace_root = environment.workspace_root()?;
    let resolver = WorkspaceResolver::new(workspace_root).map_err(path_boundary_to_io)?;
    let file = match resolver.resolve_existing_file(Path::new(file_path), path_guard) {
        Ok(file) => file,
        Err(error) => {
            if let Some(rejection) = cat_path_boundary_rejection(&error, output)? {
                return Err(rejection);
            }
            return Err(path_boundary_to_io(error));
        }
    };

    // Read through the canonical target carried by the private capability.
    let bytes = resolver.read_file(&file)?;
    let content = String::from_utf8_lossy(&bytes).into_owned();

    // シークレット候補があれば原則BLOCK
    if redactor.has_secret(&content) {
        let redacted = redactor.redact(&content);
        let redactions = Redactor::count_redactions(&content, &redacted);
        let status = blocked_cat_output("secret_detected", "", redactions);
        let warnings = injector.detect_injection(&redacted);
        let rendered = output.emit_stdout_prepared(&status, PromptInjectionAction::Warn, false)?;

        let raw_bytes = bytes.len();
        let returned_bytes = rendered.content().map_or(0, str::len);
        let reduction = if raw_bytes > 0 {
            ((raw_bytes as f64 - returned_bytes as f64) / raw_bytes as f64) * 100.0
        } else {
            0.0
        };

        let stats = Stats {
            run_id: Uuid::new_v4().to_string(),
            command: Some(redactor.redact(&format!("cat {file_path}"))),
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

        print_stats_to_stderr(&stats, redactor, output)?;
        let stored_content = safety::empty_stored_content();
        let receipt = persist_stats(persistence, &stats, &stored_content, "cat");
        print_storage_receipt(&receipt, output)?;

        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            CAT_SECRET_BLOCKED_ERROR,
        ));
    }

    let redacted_for_scan = redactor.redact(&content);
    let scan_redactions = Redactor::count_redactions(&content, &redacted_for_scan);
    let warnings = injector.detect_injection(&redacted_for_scan);
    if warnings > 0 && config.prompt_injection_action == PromptInjectionAction::Block {
        let status = blocked_cat_output("prompt_injection_detected", "", scan_redactions);
        let rendered = output.emit_stdout_prepared(&status, PromptInjectionAction::Warn, false)?;

        let raw_bytes = bytes.len();
        let returned_bytes = rendered.content().map_or(0, str::len);
        let reduction = if raw_bytes > 0 {
            ((raw_bytes as f64 - returned_bytes as f64) / raw_bytes as f64) * 100.0
        } else {
            0.0
        };

        let stats = Stats {
            run_id: Uuid::new_v4().to_string(),
            command: Some(redactor.redact(&format!("cat {file_path}"))),
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

        print_stats_to_stderr(&stats, redactor, output)?;
        let stored_content = safety::empty_stored_content();
        let receipt = persist_stats(persistence, &stats, &stored_content, "cat");
        print_storage_receipt(&receipt, output)?;

        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            CAT_PROMPT_INJECTION_BLOCKED_ERROR,
        ));
    }

    // Keep the raw UTF-8 representation for persistence while the output
    // path receives its own filtered copy.
    let content_for_store = content.clone();
    let redacted = if path_guard.should_redact(file_path) {
        redactor.redact(&content)
    } else {
        content.clone()
    };

    let truncated = truncator::truncate(&redacted, config.max_chars);
    let truncated_flag = redacted.chars().count() > config.max_chars;
    let filtered = final_output_filter(&truncated, redactor);

    // インジェクション警告
    let warnings = injector.detect_injection(&filtered.content);
    if warnings > 0 {
        output.emit_stderr("WARNING: possible prompt-injection text detected.")?;
    }

    let rendered = output.emit_stdout_prepared(
        &filtered.content,
        config.prompt_injection_action,
        truncated_flag,
    )?;

    // stats記録
    let raw_bytes = bytes.len();
    let returned_bytes = rendered.content().map_or(0, str::len);
    let reduction = if raw_bytes > 0 {
        ((raw_bytes as f64 - returned_bytes as f64) / raw_bytes as f64) * 100.0
    } else {
        0.0
    };
    let reduction = reduction.max(0.0);

    let stats = Stats {
        run_id: Uuid::new_v4().to_string(),
        command: Some(redactor.redact(&format!("cat {file_path}"))),
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

    print_stats_to_stderr(&stats, redactor, output)?;
    let stored_content = safety::sanitize_for_storage(&content_for_store, "", redactor);
    let receipt = persist_stats(persistence, &stats, &stored_content, "cat");
    print_storage_receipt(&receipt, output)?;

    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "WB-15-002: retain the migrated grep boundary until the application context refactor"
)]
fn handle_grep(
    pattern: &str,
    target_path: &str,
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    config: &config::Config,
    environment: &dyn EnvironmentAdapter,
    output: &mut OutputRouter<'_>,
    persistence: &mut Persistence,
) -> io::Result<()> {
    let workspace_root = environment.workspace_root()?;
    let resolver = WorkspaceResolver::new(workspace_root).map_err(path_boundary_to_io)?;
    let target = resolver
        .resolve_existing(Path::new(target_path), path_guard)
        .map_err(path_boundary_to_io)?;
    let outcome = resolver.grep(target, pattern, path_guard)?;

    let (results, grep_redactions) = render_grep_matches(&outcome, redactor);

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
        output.emit_stderr("WARNING: possible prompt-injection text detected.")?;
    }

    if outcome.completeness.is_partial() {
        let diagnostics = format_traversal_diagnostics(&outcome, redactor);
        output.emit_stderr_prepared(&diagnostics, PromptInjectionAction::Warn, false)?;
    }

    let rendered = output.emit_stdout_prepared(
        &filtered.content,
        config.prompt_injection_action,
        truncated_flag,
    )?;

    if rendered.is_blocked() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            GREP_PROMPT_INJECTION_BLOCKED_ERROR,
        ));
    }

    // stats記録
    let returned_bytes = rendered.content().map_or(0, str::len);
    let reduction = if raw_bytes > 0 {
        ((raw_bytes as f64 - returned_bytes as f64) / raw_bytes as f64) * 100.0
    } else {
        0.0
    };
    let reduction = reduction.max(0.0);

    let stats = Stats {
        run_id: Uuid::new_v4().to_string(),
        command: Some(redactor.redact(&format!("grep {pattern} {target_path}"))),
        exit_code: Some(if outcome.completeness.is_partial() {
            2
        } else {
            0
        }),
        raw_bytes,
        returned_bytes,
        reduction,
        redactions: grep_redactions + filtered.redactions,
        prompt_injection_warnings: warnings,
        truncated: truncated_flag,
        timeout: false,
        timestamp: Utc::now().to_rfc3339(),
    };

    print_stats_to_stderr(&stats, redactor, output)?;
    let stored_content = safety::sanitize_for_storage(&raw_results, "", redactor);
    let receipt = persist_stats(persistence, &stats, &stored_content, "grep");
    print_storage_receipt(&receipt, output)?;

    if outcome.completeness == TraversalCompleteness::Partial {
        Err(io::Error::other(GREP_PARTIAL_ERROR))
    } else {
        Ok(())
    }
}

fn render_grep_matches(outcome: &GrepOutcome, redactor: &Redactor) -> (Vec<String>, usize) {
    let mut results = Vec::with_capacity(outcome.matches.len());
    let mut redactions = 0;

    for matched in &outcome.matches {
        let processed_line = redactor.redact(&matched.content);
        redactions += Redactor::count_redactions(&matched.content, &processed_line);
        results.push(format!(
            "{}:{}:{}",
            matched.display_path.display(),
            matched.line_number,
            processed_line
        ));
    }

    (results, redactions)
}

fn format_traversal_diagnostics(outcome: &GrepOutcome, redactor: &Redactor) -> String {
    let mut output = format!(
        "traversal_status: partial\ntraversal_diagnostics: {}\n",
        outcome.diagnostics.len()
    );
    for diagnostic in &outcome.diagnostics {
        output.push_str(&format!(
            "traversal_diagnostic: {} path: {}\n",
            diagnostic.kind().label(),
            diagnostic.display_path().display()
        ));
    }
    final_output_filter(&output, redactor).content
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

#[expect(
    clippy::too_many_arguments,
    reason = "WB-15-003: retain the migrated run boundary until the application context refactor"
)]
fn handle_run(
    command_args: &[String],
    report_json: Option<&str>,
    path_guard: &PathGuard,
    redactor: &Redactor,
    injector: &Injector,
    config: &config::Config,
    environment: &dyn EnvironmentAdapter,
    process: &dyn ProcessAdapter,
    output: &mut OutputRouter<'_>,
    persistence: &mut Persistence,
) -> io::Result<()> {
    for arg in command_args {
        if let Some(path_rule) = path_guard.block_rule(arg) {
            let status = blocked_cat_output("path_blocked", path_rule, 0);
            output.emit_stdout_prepared(&status, PromptInjectionAction::Warn, false)?;

            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                RUN_PATH_BLOCKED_ERROR,
            ));
        }
    }

    let timeout_dur = Duration::from_secs(config.timeout_seconds);
    let res = executor::execute_command_with_adapters(
        command_args,
        path_guard,
        redactor,
        injector,
        timeout_dur,
        config.max_chars,
        environment,
        process,
    )?;

    let stdout_render = output.emit_stdout_prepared(
        &res.stdout,
        config.prompt_injection_action,
        res.stats.truncated,
    )?;
    let stderr_render = output.emit_stderr_prepared(
        &res.stderr,
        config.prompt_injection_action,
        res.stats.truncated,
    )?;

    if stdout_render.is_blocked() || stderr_render.is_blocked() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            RUN_PROMPT_INJECTION_BLOCKED_ERROR,
        ));
    }

    // インジェクション警告の検出確認
    if res.stats.prompt_injection_warnings > 0 {
        output.emit_stderr("WARNING: possible prompt-injection text detected.")?;
    }

    // stats記録と表示
    let mut stats = res.stats.clone();
    stats.returned_bytes =
        stdout_render.content().map_or(0, str::len) + stderr_render.content().map_or(0, str::len);
    let raw_bytes = stats.raw_bytes;
    stats.reduction = if raw_bytes > 0 {
        ((raw_bytes as f64 - stats.returned_bytes as f64) / raw_bytes as f64) * 100.0
    } else {
        0.0
    };
    stats.reduction = stats.reduction.max(0.0);

    let stored_content =
        safety::sanitize_for_storage(&res.stored_stdout, &res.stored_stderr, redactor);
    let receipt = persist_stats(persistence, &stats, &stored_content, "run");
    if let Some(path) = report_json {
        write_stats_json(path, &stats)?;
    }
    print_stats_to_stderr(&stats, redactor, output)?;
    print_storage_receipt(&receipt, output)?;

    if let Some(code) = res.stats.exit_code {
        std::process::exit(code);
    } else {
        std::process::exit(0);
    }
}

fn persist_stats(
    persistence: &mut Persistence,
    stats: &Stats,
    content: &SanitizedStoredContent,
    command_kind: &str,
) -> StorageReceipt {
    persistence.store(stats, content, command_kind)
}

fn print_storage_receipt(
    receipt: &StorageReceipt,
    output: &mut OutputRouter<'_>,
) -> io::Result<()> {
    // A successfully stored run already exposes its run_id through the
    // existing stats block. Keep the Level 1 contract stable; explicit
    // no-store and failure receipts must still be visible.
    if receipt.stored {
        return Ok(());
    }
    let mut content = format!(
        "[llm-veil storage]\nrun_id: {}\nstored: {}\nretrievable: {}\nstorage_reason: {}",
        receipt.run_id,
        receipt.stored,
        receipt.retrievable,
        receipt.reason.as_str()
    );
    if let Some(expires_at) = receipt.expires_at {
        content.push_str(&format!("\nexpires_at_unix: {expires_at}"));
    }
    output
        .emit_stderr_prepared(&content, PromptInjectionAction::Warn, false)
        .map(|_| ())
}

fn parse_stream(value: &str) -> io::Result<Stream> {
    match value {
        "stdout" => Ok(Stream::Stdout),
        "stderr" => Ok(Stream::Stderr),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream must be stdout or stderr",
        )),
    }
}

fn lookup_status_error(status: LookupStatus, run_id: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("run_id: {}\nstatus: {}", run_id, status.as_str()),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "WB-15-004: retain the migrated retrieve boundary until the application context refactor"
)]
fn handle_retrieve(
    run_id: &str,
    stream_text: &str,
    start_line: u64,
    lines: u32,
    redactor: &Redactor,
    injector: &Injector,
    config: &config::Config,
    environment: &dyn EnvironmentAdapter,
    output: &mut OutputRouter<'_>,
) -> io::Result<()> {
    let stream = parse_stream(stream_text)?;
    let mut store = RunStore::open_default_with(environment)?;
    let result = store.retrieve_lines_at(
        run_id,
        stream,
        start_line,
        lines,
        redactor,
        injector,
        config.prompt_injection_action,
        config.max_chars,
        Utc::now().timestamp(),
    )?;
    if result.status != LookupStatus::Active {
        if result.status == LookupStatus::Blocked {
            let blocked_render = output::render_external(
                &format!(
                    "status: blocked\nrun_id: {}\nstream: {}\nprompt_injection: true",
                    result.run_id,
                    result.stream.as_str()
                ),
                redactor,
                injector,
                PromptInjectionAction::Warn,
                config.max_chars,
            );
            output.emit_stdout_render(&blocked_render)?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retrieval blocked by prompt-injection policy",
            ));
        }
        return Err(lookup_status_error(result.status, run_id));
    }
    if let Some(content) = result.content.as_ref() {
        output.emit_stdout_render(content)?;
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "WB-15-005: retain the migrated search boundary until the application context refactor"
)]
fn handle_search(
    run_id: &str,
    stream_text: &str,
    literal: &str,
    cursor: Option<&str>,
    redactor: &Redactor,
    injector: &Injector,
    config: &config::Config,
    environment: &dyn EnvironmentAdapter,
    output: &mut OutputRouter<'_>,
) -> io::Result<()> {
    let stream = parse_stream(stream_text)?;
    let mut store = RunStore::open_default_with(environment)?;
    let result = store.search_at(run_id, stream, literal, cursor, Utc::now().timestamp())?;
    if result.status != LookupStatus::Active {
        return Err(lookup_status_error(result.status, run_id));
    }

    let mut body = format!(
        "status: active\nrun_id: {}\nstream: {}\nmatches: {}\n",
        result.run_id,
        result.stream.as_str(),
        result.matches.len()
    );
    if result.scan_truncated {
        body.push_str("scan_truncated: true\n");
    }
    if let Some(next_cursor) = &result.next_cursor {
        body.push_str(&format!("next_cursor: {next_cursor}\n"));
    }
    for matched in &result.matches {
        body.push_str(&format!("line {}: {}\n", matched.line, matched.content));
    }

    let mut render = output::render_external(
        &body,
        redactor,
        injector,
        config.prompt_injection_action,
        config.max_chars,
    );
    if !render.is_blocked() && render.injection_warnings() > 0 {
        body = format!(
            "prompt_injection_warnings: {}\n{}",
            render.injection_warnings(),
            body
        );
        render = output::render_external(
            &body,
            redactor,
            injector,
            config.prompt_injection_action,
            config.max_chars,
        );
    }
    if render.is_blocked() {
        let blocked_render = output::render_external(
            &format!(
                "status: blocked\nrun_id: {}\nstream: {}\nprompt_injection: true",
                run_id,
                stream.as_str()
            ),
            redactor,
            injector,
            PromptInjectionAction::Warn,
            config.max_chars,
        );
        output.emit_stdout_render(&blocked_render)?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "search blocked by prompt-injection policy",
        ));
    }
    output.emit_stdout_render(&render)?;
    Ok(())
}

fn handle_store(
    command: cli::StoreCommands,
    environment: &dyn EnvironmentAdapter,
    output: &mut OutputRouter<'_>,
) -> io::Result<()> {
    let mut store = RunStore::open_default_with(environment)?;
    match command {
        cli::StoreCommands::Delete { run_id } => match store.delete(&run_id)? {
            DeleteStatus::Deleted => {
                output.emit_stdout_prepared(
                    &format!("run_id: {run_id}\nstatus: deleted"),
                    PromptInjectionAction::Warn,
                    false,
                )?;
            }
            DeleteStatus::AlreadyGone => {
                output.emit_stdout_prepared(
                    &format!("run_id: {run_id}\nstatus: already_gone"),
                    PromptInjectionAction::Warn,
                    false,
                )?;
            }
            DeleteStatus::NotFound => {
                return Err(lookup_status_error(LookupStatus::NotFound, &run_id));
            }
        },
        cli::StoreCommands::Purge { expired, all } => {
            if !expired && !all {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "choose --expired or --all",
                ));
            }
            let removed = store.purge(expired && !all)?;
            output.emit_stdout_prepared(
                &format!("status: purged\nremoved: {removed}"),
                PromptInjectionAction::Warn,
                false,
            )?;
        }
        cli::StoreCommands::Status => {
            let status = store.status()?;
            output.emit_stdout_prepared(
                &format!(
                    "root: {}\nactive_records: {}\ntombstones: {}\nttl_seconds: {}\nmax_stream_bytes: {}\nmax_total_bytes: {}\nmax_records: {}",
                    status.root.display(),
                    status.active_records,
                    status.tombstones,
                    status.config.ttl_secs,
                    status.config.max_stream_bytes,
                    status.config.max_total_bytes,
                    status.config.max_records
                ),
                PromptInjectionAction::Warn,
                false,
            )?;
        }
    }
    Ok(())
}

fn handle_report(
    run_id: Option<&str>,
    redactor: &Redactor,
    environment: &dyn EnvironmentAdapter,
    output: &mut OutputRouter<'_>,
) -> io::Result<()> {
    let stats = match RunStore::open_default_with(environment) {
        Ok(mut store) => match store.load_stats(run_id) {
            Ok(stats) => stats,
            Err(error)
                if matches!(
                    error.to_string().as_str(),
                    "status: expired"
                        | "status: deleted"
                        | "status: corrupt"
                        | "status: storage_error"
                ) =>
            {
                return Err(error);
            }
            Err(_) => {
                if let Some(id) = run_id {
                    stats::load_stats(id)?
                } else {
                    stats::load_last_stats()?
                }
            }
        },
        Err(_) => {
            if let Some(id) = run_id {
                stats::load_stats(id)?
            } else {
                stats::load_last_stats()?
            }
        }
    };
    let report = format_report_output(&stats, redactor);
    output.emit_stdout_prepared(&report, PromptInjectionAction::Warn, false)?;

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

fn print_stats_to_stderr(
    stats: &Stats,
    redactor: &Redactor,
    output: &mut OutputRouter<'_>,
) -> io::Result<()> {
    let content = format_stats_for_stderr(stats, redactor);
    output
        .emit_stderr_prepared(&content, PromptInjectionAction::Warn, false)
        .map(|_| ())
}

fn format_stats_for_stderr(stats: &Stats, redactor: &Redactor) -> String {
    let mut output = String::new();

    output.push_str("\n[llm-veil stats]\n");
    output.push_str(&format!("run_id: {}\n", stats.run_id));
    if let Some(cmd) = &stats.command {
        output.push_str(&format!("command: {}\n", redactor.redact(cmd)));
    }
    if let Some(code) = stats.exit_code {
        output.push_str(&format!("exit_code: {code}\n"));
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

    final_output_filter(&output, redactor).content
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_grep_file_redacts_secret_on_allowed_path() {
        let environment = SystemEnvironment;
        let file_path = environment
            .current_dir()
            .unwrap()
            .join(format!("llm-veil-grep-{}.txt", Uuid::new_v4()));
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "const token = \"my_jwt_token\";").unwrap();

        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let resolver = WorkspaceResolver::new(environment.current_dir().unwrap()).unwrap();
        let file = resolver
            .resolve_existing_file(&file_path, &path_guard)
            .unwrap();
        let outcome = resolver
            .grep(
                path_io::ExistingWorkspaceTarget::File(file),
                "token",
                &path_guard,
            )
            .unwrap();
        let (results, redactions) = render_grep_matches(&outcome, &redactor);
        fs::remove_file(&file_path).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(redactions, 1);
        assert!(results[0].contains("const token = \"[REDACTED_SECRET]\";"));
        assert!(!results[0].contains("my_jwt_token"));
    }

    #[test]
    fn test_handle_cat_blocks_secrets() {
        let environment = SystemEnvironment;
        let file_path = environment
            .current_dir()
            .unwrap()
            .join(format!("llm-veil-cat-{}.txt", Uuid::new_v4()));
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "export API_KEY=AIzaSyAThisIsAFakeApiKeyForTesting").unwrap();

        let path_guard = PathGuard::new(vec![], PathAction::Allow).unwrap();
        let redactor = Redactor::new();
        let injector = Injector::new();
        let environment = SystemEnvironment;
        let config = config::Config {
            action: PathAction::Allow,
            prompt_injection_action: PromptInjectionAction::Block,
            timeout_seconds: 10,
            max_chars: 1000,
            blocked_patterns: vec![],
        };
        let mut persistence = Persistence::new_with_environment(true, &environment);
        let mut std_output = StdOutputAdapter;
        let mut output = OutputRouter::new(
            &mut std_output,
            &redactor,
            &injector,
            config.prompt_injection_action,
            config.max_chars,
        );

        let res = handle_cat(
            file_path.to_str().unwrap(),
            &path_guard,
            &redactor,
            &injector,
            &config,
            &environment,
            &mut output,
            &mut persistence,
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
    fn test_stats_stderr_formatter_applies_final_redactor_to_whole_output() {
        let redactor = Redactor::new();
        let stats = Stats {
            run_id: "SECRET_KEY=12345".to_string(),
            command: Some("safe command".to_string()),
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

        assert!(output.contains("run_id: SECRET_KEY=[REDACTED_SECRET]"));
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

    #[test]
    fn test_error_formatter_applies_final_redactor() {
        let redactor = Redactor::new();
        let output = format_error_for_stderr("failed with SECRET_KEY=12345", &redactor);

        assert!(output.contains("Error: failed with SECRET_KEY=[REDACTED_SECRET]"));
        assert!(!output.contains("12345"));
    }
}
