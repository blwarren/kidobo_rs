use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use log::LevelFilter;

#[derive(Debug, Parser)]
#[command(
    name = "kidobo",
    version,
    about = "One-shot firewall blocklist manager",
    long_about = "Manage Kidobo firewall blocklists with one-shot commands (no daemon/background service).",
    after_help = "Examples:\n  kidobo init\n  kidobo sync\n  kidobo lookup 203.0.113.7\n  kidobo lookup --file ./targets.txt\n  kidobo ban 203.0.113.0/24\n  kidobo unban 203.0.113.7 --yes"
)]
pub struct Cli {
    #[arg(
        long = "log-level",
        value_enum,
        default_value_t = LogLevel::Info,
        global = true,
        help = "Set stderr log verbosity"
    )]
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
    #[command(about = "Create missing config/data/cache files and systemd units")]
    Init,
    #[command(about = "Run environment checks and print a JSON report")]
    Doctor,
    #[command(about = "Sync local+remote blocklists into firewall/ipset state")]
    Sync,
    #[command(about = "Best-effort cleanup of kidobo runtime state")]
    Flush {
        #[arg(
            long = "cache-only",
            help = "Only clear cached remote source files (leave firewall/ipset state unchanged)"
        )]
        cache_only: bool,
    },
    #[command(about = "Add an IP/CIDR entry to the local blocklist")]
    Ban {
        #[arg(value_name = "IP_OR_CIDR", help = "IPv4/IPv6 address or CIDR to add")]
        target: String,
    },
    #[command(about = "Remove an IP/CIDR entry from the local blocklist")]
    Unban {
        #[arg(
            value_name = "IP_OR_CIDR",
            help = "IPv4/IPv6 address or CIDR to remove"
        )]
        target: String,

        #[arg(
            long,
            help = "Skip confirmation and remove overlapping entries if needed"
        )]
        yes: bool,
    },
    #[command(
        about = "Offline lookup against local blocklist + cached remote sources",
        long_about = "Lookup runs offline only and never fetches remote sources."
    )]
    Lookup {
        #[arg(
            value_name = "IP_OR_CIDR",
            help = "Single target IP/CIDR to match",
            conflicts_with = "file",
            required_unless_present = "file"
        )]
        ip: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            help = "File with one target IP/CIDR per line",
            conflicts_with = "ip",
            required_unless_present = "ip"
        )]
        file: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, LogLevel};
    use clap::Parser;
    use log::LevelFilter;

    #[test]
    fn log_level_mapping_matches_rust_levels() {
        assert_eq!(LevelFilter::from(LogLevel::Trace), LevelFilter::Trace);
        assert_eq!(LevelFilter::from(LogLevel::Debug), LevelFilter::Debug);
        assert_eq!(LevelFilter::from(LogLevel::Info), LevelFilter::Info);
        assert_eq!(LevelFilter::from(LogLevel::Warn), LevelFilter::Warn);
        assert_eq!(LevelFilter::from(LogLevel::Error), LevelFilter::Error);
    }

    #[test]
    fn flush_cache_only_flag_is_parsed() {
        let cli = Cli::try_parse_from(["kidobo", "flush", "--cache-only"]).expect("flush parse");
        match cli.command {
            Command::Flush { cache_only } => assert!(cache_only),
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn ban_command_parses_target() {
        let cli = Cli::try_parse_from(["kidobo", "ban", "203.0.113.7"]).expect("ban parse");
        match cli.command {
            Command::Ban { target } => assert_eq!(target, "203.0.113.7"),
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn unban_command_parses_yes_flag() {
        let cli = Cli::try_parse_from(["kidobo", "unban", "203.0.113.0/24", "--yes"])
            .expect("unban parse");
        match cli.command {
            Command::Unban { target, yes } => {
                assert_eq!(target, "203.0.113.0/24");
                assert!(yes);
            }
            _ => panic!("unexpected command variant"),
        }
    }
}
