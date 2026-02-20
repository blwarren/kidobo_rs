use std::path::PathBuf;

use log::warn;

use crate::adapters::blocklist_analysis_sources::load_analysis_sources;
use crate::adapters::config::load_config_from_file;
use crate::adapters::limited_io::read_to_string_with_limit;
use crate::adapters::lookup_sources::load_lookup_sources;
use crate::adapters::path::{PathResolutionInput, resolve_paths};
use crate::cli::args::{AnalyzeCommand, Command};
use crate::cli::blocklist::{run_ban_command, run_unban_command};
use crate::cli::doctor::run_doctor_command;
use crate::cli::flush::run_flush_command;
use crate::cli::init::run_init_command;
use crate::cli::sync::run_sync_command;
use crate::core::blocklist_analysis::{
    collapse_by_family, fully_covered_local, overlap_counts, subtract_remote_from_local,
};
use crate::core::lookup::run_lookup_streaming;
use crate::error::KidoboError;

const LOOKUP_TARGET_READ_LIMIT: usize = 2 * 1024 * 1024;

pub fn dispatch(command: Command) -> Result<(), KidoboError> {
    match command {
        Command::Init => run_init_command(),
        Command::Doctor => run_doctor_command(),
        Command::Sync => run_sync_command(),
        Command::Flush { cache_only } => run_flush_command(cache_only),
        Command::Lookup { ip, file } => run_lookup_command(ip, file),
        Command::Analyze { command } => match command {
            AnalyzeCommand::Overlap {
                print_fully_covered_local,
                print_reduced_local,
            } => run_analyze_overlap_command(print_fully_covered_local, print_reduced_local),
        },
        Command::Ban { target } => run_ban_command(&target),
        Command::Unban { target, yes } => run_unban_command(&target, yes),
    }
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn run_lookup_command(ip: Option<String>, file: Option<PathBuf>) -> Result<(), KidoboError> {
    let targets = collect_lookup_targets(ip, file)?;

    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;

    let _config = load_config_from_file(&paths.config_file)?;
    let sources = load_lookup_sources(&paths)?;

    let invalid_targets = run_lookup_streaming(&targets, &sources, |target, source| {
        println!("{target}\t{}\t{}", source.source_label, source.source_line);
    });

    for invalid in &invalid_targets {
        eprintln!("invalid target: {invalid}");
    }

    if !invalid_targets.is_empty() {
        return Err(KidoboError::LookupInvalidTargets {
            count: invalid_targets.len(),
        });
    }

    Ok(())
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn run_analyze_overlap_command(
    print_fully_covered_local: bool,
    print_reduced_local: bool,
) -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
    let config = load_config_from_file(&paths.config_file)?;
    let stale_after_secs = u64::from(config.remote.cache_stale_after_secs);
    let sources = load_analysis_sources(&paths, stale_after_secs).map_err(KidoboError::from)?;

    let local = collapse_by_family(&sources.local_cidrs);
    let remote_all = sources
        .remote_sources
        .iter()
        .flat_map(|source| source.cidrs.iter().copied())
        .collect::<Vec<_>>();
    let remote_union = collapse_by_family(&remote_all);

    let union_overlap = overlap_counts(&local, &remote_union);
    let fully_covered = fully_covered_local(&local, &remote_union);
    let reduced = subtract_remote_from_local(&local, &remote_union);

    let stale_sources = sources
        .remote_sources
        .iter()
        .filter(|source| source.stale)
        .collect::<Vec<_>>();
    for stale in &stale_sources {
        if let Some(age_secs) = stale.age_secs {
            warn!(
                "stale remote cache source detected: source={} age_secs={} threshold_secs={}",
                stale.label, age_secs, stale_after_secs
            );
        } else {
            warn!(
                "stale remote cache source detected: source={} age_secs=unknown threshold_secs={}",
                stale.label, stale_after_secs
            );
        }
    }

    println!("analyze overlap (offline cache only)");
    println!(
        "local collapsed entries: ipv4={} ipv6={} total={}",
        local.ipv4.len(),
        local.ipv6.len(),
        local.ipv4.len() + local.ipv6.len()
    );
    println!(
        "remote cached sources: total={} stale={} stale_after_secs={}",
        sources.remote_sources.len(),
        stale_sources.len(),
        stale_after_secs
    );
    println!(
        "remote union collapsed entries: ipv4={} ipv6={} total={}",
        remote_union.ipv4.len(),
        remote_union.ipv6.len(),
        remote_union.ipv4.len() + remote_union.ipv6.len()
    );
    println!(
        "local overlap with remote union: overlapping_ipv4={} overlapping_ipv6={} fully_covered_ipv4={} fully_covered_ipv6={}",
        union_overlap.ipv4.overlapping,
        union_overlap.ipv6.overlapping,
        union_overlap.ipv4.fully_covered,
        union_overlap.ipv6.fully_covered
    );
    println!(
        "local reduction options: remove_fully_covered_count={} reduced_local_count={}",
        fully_covered.ipv4.len() + fully_covered.ipv6.len(),
        reduced.ipv4.len() + reduced.ipv6.len()
    );

    if !sources.remote_sources.is_empty() {
        println!("per-remote overlap:");
        for source in &sources.remote_sources {
            let source_family = collapse_by_family(&source.cidrs);
            let overlap = overlap_counts(&local, &source_family);
            println!(
                "{}\toverlap_ipv4={}\toverlap_ipv6={}\tfully_covered_ipv4={}\tfully_covered_ipv6={}\tstale={}",
                source.label,
                overlap.ipv4.overlapping,
                overlap.ipv6.overlapping,
                overlap.ipv4.fully_covered,
                overlap.ipv6.fully_covered,
                source.stale
            );
        }
    }

    if print_fully_covered_local {
        println!();
        println!("# local entries fully covered by remote union");
        for cidr in format_family_cidrs(&fully_covered.ipv4, &fully_covered.ipv6) {
            println!("{cidr}");
        }
    }

    if print_reduced_local {
        println!();
        println!("# suggested reduced local blocklist (local minus remote union)");
        for cidr in format_family_cidrs(&reduced.ipv4, &reduced.ipv6) {
            println!("{cidr}");
        }
    }

    Ok(())
}

fn collect_lookup_targets(
    ip: Option<String>,
    file: Option<PathBuf>,
) -> Result<Vec<String>, KidoboError> {
    match (ip, file) {
        (Some(target), None) => Ok(vec![target]),
        (None, Some(path)) => read_target_lines(&path),
        _ => Ok(Vec::new()),
    }
}

fn read_target_lines(path: &std::path::Path) -> Result<Vec<String>, KidoboError> {
    let contents = read_to_string_with_limit(path, LOOKUP_TARGET_READ_LIMIT).map_err(|err| {
        KidoboError::LookupTargetFileRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    Ok(contents.lines().map(ToString::to_string).collect())
}

fn format_family_cidrs<T: ToString, U: ToString>(ipv4: &[T], ipv6: &[U]) -> Vec<String> {
    let mut lines = Vec::with_capacity(ipv4.len() + ipv6.len());
    lines.extend(ipv4.iter().map(ToString::to_string));
    lines.extend(ipv6.iter().map(ToString::to_string));
    lines
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::{collect_lookup_targets, format_family_cidrs, read_target_lines};
    use crate::core::network::CanonicalCidr;
    use crate::error::KidoboError;

    #[test]
    fn lookup_target_collection_single_mode() {
        let targets =
            collect_lookup_targets(Some("203.0.113.7".to_string()), None).expect("collect");
        assert_eq!(targets, vec!["203.0.113.7"]);
    }

    #[test]
    fn lookup_target_collection_file_mode() {
        let temp = TempDir::new().expect("tempdir");
        let file = temp.path().join("targets.txt");
        fs::write(&file, "10.0.0.1\n2001:db8::1\n").expect("write");

        let targets = collect_lookup_targets(None, Some(file)).expect("collect");
        assert_eq!(targets, vec!["10.0.0.1", "2001:db8::1"]);
    }

    #[test]
    fn read_target_lines_reports_file_read_error() {
        let missing = PathBuf::from("/definitely/missing/targets.txt");
        let err = read_target_lines(&missing).expect_err("must fail");
        match err {
            KidoboError::LookupTargetFileRead { path, .. } => assert_eq!(path, missing),
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn format_family_cidrs_orders_ipv4_then_ipv6() {
        let lines = format_family_cidrs(
            &[CanonicalCidr::V4(
                crate::core::network::Ipv4Cidr::from_parts(0xcb007107, 32),
            )],
            &[CanonicalCidr::V6(
                crate::core::network::Ipv6Cidr::from_parts(0x20010db8000000000000000000000001, 128),
            )],
        );
        assert_eq!(lines, vec!["203.0.113.7/32", "2001:db8::1/128"]);
    }
}
