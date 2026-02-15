use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use log::LevelFilter;

#[derive(Debug, Parser)]
#[command(
    name = "kidobo",
    version,
    about = "One-shot firewall blocklist manager"
)]
pub struct Cli {
    #[arg(long = "log-level", value_enum, default_value_t = LogLevel::Info, global = true)]
    pub log_level: LogLevel,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => LevelFilter::Trace,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init,
    Doctor,
    Sync,
    Flush,
    Lookup {
        #[arg(
            value_name = "ip",
            conflicts_with = "file",
            required_unless_present = "file"
        )]
        ip: Option<String>,

        #[arg(
            long,
            value_name = "path",
            conflicts_with = "ip",
            required_unless_present = "ip"
        )]
        file: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use super::LogLevel;
    use log::LevelFilter;

    #[test]
    fn log_level_mapping_matches_rust_levels() {
        assert_eq!(LevelFilter::from(LogLevel::Trace), LevelFilter::Trace);
        assert_eq!(LevelFilter::from(LogLevel::Debug), LevelFilter::Debug);
        assert_eq!(LevelFilter::from(LogLevel::Info), LevelFilter::Info);
        assert_eq!(LevelFilter::from(LogLevel::Warn), LevelFilter::Warn);
        assert_eq!(LevelFilter::from(LogLevel::Error), LevelFilter::Error);
    }
}
