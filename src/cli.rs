use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "veil")]
#[command(about = "llm-veil: A local safety filter for AI-assisted development", long_about = None)]
pub struct Cli {
    /// Override the safety action (block, redact, allow)
    #[arg(long, value_parser = ["block", "redact", "allow"])]
    pub action: Option<String>,

    /// Override the timeout limit in seconds
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Override the max characters limit
    #[arg(long)]
    pub max_chars: Option<usize>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Read a file safely
    Cat {
        /// Do not persist body, stats, command history, or last_run
        #[arg(long)]
        no_store: bool,
        file: String,
    },
    /// Search patterns in path safely
    Grep {
        /// Do not persist body, stats, command history, or last_run
        #[arg(long)]
        no_store: bool,
        pattern: String,
        path: Option<String>,
    },
    /// Run command safely
    Run {
        /// Write sanitized execution metadata JSON to this file
        #[arg(long)]
        report_json: Option<String>,

        /// Do not persist body, stats, command history, or last_run
        #[arg(long)]
        no_store: bool,

        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// View stats of the execution
    Report { run_id: Option<String> },
    /// Retrieve a bounded line range from a stored run
    Retrieve {
        run_id: String,
        #[arg(long, value_parser = ["stdout", "stderr"])]
        stream: String,
        #[arg(long, default_value_t = 0)]
        start_line: u64,
        #[arg(long, default_value_t = 50)]
        lines: u32,
    },
    /// Search a stored run using a bounded literal scan
    Search {
        run_id: String,
        #[arg(long, value_parser = ["stdout", "stderr"])]
        stream: String,
        #[arg(long)]
        literal: String,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Manage retained runs
    Store {
        #[command(subcommand)]
        command: StoreCommands,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum StoreCommands {
    /// Delete one stored run
    Delete { run_id: String },
    /// Remove expired records or all records and tombstones
    Purge {
        #[arg(long, conflicts_with = "all")]
        expired: bool,
        #[arg(long, conflicts_with = "expired")]
        all: bool,
    },
    /// Show safe retention configuration and counts
    Status,
}
