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
        file: String,
    },
    /// Search patterns in path safely
    Grep {
        pattern: String,
        path: Option<String>,
    },
    /// Run command safely
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// View stats of the execution
    Report {
        run_id: Option<String>,
    },
}
