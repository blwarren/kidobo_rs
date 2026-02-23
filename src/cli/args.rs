use std::path::PathBuf;

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
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
        long_about = "Add one IPv4/IPv6 address or CIDR entry to the local blocklist file, or ban one or more ASNs with `--asn`.\n\nThis updates local source data only; run `kidobo sync` to apply changes to firewall/ipset state."
    )]
    Ban {
        #[arg(
            value_name = "IP_OR_CIDR",
            help = "IPv4/IPv6 address or CIDR to add",
            conflicts_with = "asn",
            required_unless_present = "asn"
        )]
        target: Option<String>,

        #[arg(
            long = "asn",
            value_name = "ASN",
            num_args = 1..,
            help = "ASN(s) to ban (e.g. 213412 or AS213412)",
            conflicts_with = "target",
            required_unless_present = "target"
        )]
        asn: Option<Vec<String>>,
    },
    #[command(
        about = "Remove an IP/CIDR entry from the local blocklist",
        long_about = "Remove one IPv4/IPv6 address or CIDR entry from the local blocklist file, or remove one or more ASNs with `--asn`.\n\nThis updates local source data only; run `kidobo sync` to apply changes to firewall/ipset state."
    )]
    Unban {
        #[arg(
            value_name = "IP_OR_CIDR",
            help = "IPv4/IPv6 address or CIDR to remove",
            conflicts_with = "asn",
            required_unless_present = "asn"
        )]
        target: Option<String>,

        #[arg(
            long = "asn",
            value_name = "ASN",
            num_args = 1..,
            help = "ASN(s) to unban (e.g. 213412 or AS213412)",
            conflicts_with = "target",
            required_unless_present = "target"
        )]
        asn: Option<Vec<String>>,

        #[arg(
            long,
            help = "Skip confirmation and remove overlapping entries if needed"
        )]
        yes: bool,
    },
    #[command(
        about = "Offline lookup against local blocklist + cached remote sources",
        long_about = "Lookup candidate targets against local blocklist and cached remote sources.\n\nLookup runs offline only and never fetches remote sources.",
        group(
            ArgGroup::new("lookup_input")
                .args(["ip", "file"])
                .required(true)
                .multiple(false)
        )
    )]
    Lookup {
        #[arg(value_name = "IP_OR_CIDR", help = "Single target IP/CIDR to match")]
        ip: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            help = "File with one target IP/CIDR per line"
        )]
        file: Option<PathBuf>,
    },

    #[command(
        about = "Analyze local blocklist overlap against cached remote blocklists",
        long_about = "Analyze overlap between local blocklist entries and cached remote blocklists without performing any remote fetch.\n\nUse this command to identify local entries already covered by remote cached sources and generate reduced local suggestions."
    )]
    Analyze {
        #[command(subcommand)]
        command: AnalyzeCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AnalyzeCommand {
    #[command(
        about = "Analyze overlap between local blocklist and cached remote blocklists",
        long_about = "Offline-only overlap analysis using local blocklist and cached remote `.iplist` sources.\n\n`ov*` means local entries that intersect a remote source.\n`covered*` means local entries fully contained by a remote source (safe removal candidates)."
    )]
    Overlap {
        #[arg(
            long,
            help = "Print local entries fully covered by cached remote union"
        )]
        print_fully_covered_local: bool,

        #[arg(
            long,
            help = "Print suggested reduced local blocklist (local minus cached remote union)"
        )]
        print_reduced_local: bool,

        #[arg(
            long,
            help = "Apply removal of local entries fully covered by cached remote union"
        )]
        apply_fully_covered_local: bool,
    },
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{AnalyzeCommand, Cli, Command, LogLevel};
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
            Command::Ban { target, asn } => {
                assert_eq!(target, Some("203.0.113.7".to_string()));
                assert!(asn.is_none());
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn unban_command_parses_yes_flag() {
        let cli = Cli::try_parse_from(["kidobo", "unban", "203.0.113.0/24", "--yes"])
            .expect("unban parse");
        match cli.command {
            Command::Unban { target, asn, yes } => {
                assert_eq!(target, Some("203.0.113.0/24".to_string()));
                assert!(asn.is_none());
                assert!(yes);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn ban_command_parses_multiple_asns() {
        let cli =
            Cli::try_parse_from(["kidobo", "ban", "--asn", "AS213412", "64512"]).expect("parse");
        match cli.command {
            Command::Ban { target, asn } => {
                assert!(target.is_none());
                assert_eq!(asn, Some(vec!["AS213412".to_string(), "64512".to_string()]));
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn analyze_overlap_mode_parses() {
        let cli = Cli::try_parse_from(["kidobo", "analyze", "overlap"]).expect("analyze parse");
        match cli.command {
            Command::Analyze { command } => match command {
                AnalyzeCommand::Overlap {
                    print_fully_covered_local,
                    print_reduced_local,
                    apply_fully_covered_local,
                } => {
                    assert!(!print_fully_covered_local);
                    assert!(!print_reduced_local);
                    assert!(!apply_fully_covered_local);
                }
            },
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn lookup_command_parses_ip_mode() {
        let cli = Cli::try_parse_from(["kidobo", "lookup", "203.0.113.7"]).expect("lookup parse");
        match cli.command {
            Command::Lookup { ip, file } => {
                assert_eq!(ip, Some("203.0.113.7".to_string()));
                assert!(file.is_none());
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn lookup_command_parses_file_mode() {
        let cli =
            Cli::try_parse_from(["kidobo", "lookup", "--file", "targets.txt"]).expect("parse");
        match cli.command {
            Command::Lookup { ip, file } => {
                assert!(ip.is_none());
                assert_eq!(file, Some(PathBuf::from("targets.txt")));
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn lookup_command_rejects_missing_input_mode() {
        let err = Cli::try_parse_from(["kidobo", "lookup"]).expect_err("lookup must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn lookup_command_rejects_multiple_input_modes() {
        let err = Cli::try_parse_from(["kidobo", "lookup", "203.0.113.7", "--file", "targets.txt"])
            .expect_err("lookup must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
