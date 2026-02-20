use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use log::LevelFilter;

#[derive(Debug, Parser)]
#[command(
    name = "kidobo",
    version,
    about = "One-shot firewall blocklist manager",
    long_about = "Manage Kidobo firewall blocklists with one-shot commands (no daemon/background service)."
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
    #[command(
        about = "Create missing config/data/cache files and systemd units",
        long_about = "Create any missing Kidobo config/data/cache files and default systemd unit files.\n\nAt default system paths, this also runs systemctl daemon-reload, reset-failed, and enable --now for kidobo-sync.timer."
    )]
    Init,
    #[command(
        about = "Run environment checks and print a JSON report",
        long_about = "Run environment and dependency checks, then print a structured JSON report to stdout.\n\nThe command exits with code 0 when overall status is ok, and 1 when any required check fails."
    )]
    Doctor,
    #[command(
        about = "Sync local+remote blocklists into firewall/ipset state",
        long_about = "Load config and sources, apply safelist subtraction, collapse entries, then atomically update ipset state and firewall wiring.\n\nThis command is one-shot and fail-fast for hard errors (for example lock contention or invalid config)."
    )]
    Sync,
    #[command(
        about = "Best-effort cleanup of kidobo runtime state",
        long_about = "Best-effort cleanup command for Kidobo runtime artifacts.\n\nBy default it attempts firewall/ipset cleanup and remote cache cleanup. Use --cache-only to leave firewall/ipset state unchanged."
    )]
    Flush {
        #[arg(
            long = "cache-only",
            help = "Only clear cached remote source files (leave firewall/ipset state unchanged)"
        )]
        cache_only: bool,
    },
    #[command(
        about = "Add an IP/CIDR entry to the local blocklist",
        long_about = "Add one IPv4/IPv6 address or CIDR entry to the local blocklist file.\n\nThis updates local source data only; run `kidobo sync` to apply changes to firewall/ipset state."
    )]
    Ban {
        #[arg(value_name = "IP_OR_CIDR", help = "IPv4/IPv6 address or CIDR to add")]
        target: String,
    },
    #[command(
        about = "Remove an IP/CIDR entry from the local blocklist",
        long_about = "Remove one IPv4/IPv6 address or CIDR entry from the local blocklist file.\n\nThis updates local source data only; run `kidobo sync` to apply changes to firewall/ipset state."
    )]
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
        long_about = "Lookup candidate targets against local blocklist and cached remote sources.\n\nLookup runs offline only and never fetches remote sources.\n\nUse --analyze-overlap to inspect overlap between local and cached remote blocklists."
    )]
    Lookup {
        #[arg(
            value_name = "IP_OR_CIDR",
            help = "Single target IP/CIDR to match",
            conflicts_with = "file",
            required_unless_present_any = ["file", "analyze_overlap"]
        )]
        ip: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            help = "File with one target IP/CIDR per line",
            conflicts_with = "ip",
            required_unless_present_any = ["ip", "analyze_overlap"]
        )]
        file: Option<PathBuf>,

        #[arg(
            long,
            help = "Analyze overlap between local blocklist and cached remote blocklists (offline only)",
            conflicts_with_all = ["ip", "file"]
        )]
        analyze_overlap: bool,

        #[arg(
            long,
            help = "Print local entries fully covered by cached remote union (requires --analyze-overlap)",
            requires = "analyze_overlap"
        )]
        print_fully_covered_local: bool,

        #[arg(
            long,
            help = "Print suggested reduced local blocklist (local minus cached remote union; requires --analyze-overlap)",
            requires = "analyze_overlap"
        )]
        print_reduced_local: bool,
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

    #[test]
    fn lookup_analyze_overlap_mode_parses() {
        let cli = Cli::try_parse_from(["kidobo", "lookup", "--analyze-overlap"])
            .expect("lookup analyze parse");
        match cli.command {
            Command::Lookup {
                ip,
                file,
                analyze_overlap,
                print_fully_covered_local,
                print_reduced_local,
            } => {
                assert!(ip.is_none());
                assert!(file.is_none());
                assert!(analyze_overlap);
                assert!(!print_fully_covered_local);
                assert!(!print_reduced_local);
            }
            _ => panic!("unexpected command variant"),
        }
    }
}
