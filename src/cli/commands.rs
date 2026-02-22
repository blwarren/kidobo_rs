use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use log::warn;
use tabled::settings::Style;
use tabled::{Table, Tabled};

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
use crate::core::network::{CanonicalCidr, parse_ip_cidr_token, split_by_family};
use crate::error::KidoboError;

const LOOKUP_TARGET_READ_LIMIT: usize = 2 * 1024 * 1024;
const BLOCKLIST_READ_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct RemoteOverlapRow<'a> {
    label: &'a str,
    ov4: usize,
    ov6: usize,
    covered4: usize,
    covered6: usize,
    stale: bool,
}

#[derive(Debug, Clone, Copy)]
struct OverlapSummaryData {
    remote_source_count: usize,
    stale_source_count: usize,
    stale_after_secs: u64,
    fully_covered_total: usize,
    reduced_total: usize,
}

#[derive(Debug, Tabled)]
struct SummaryRow {
    metric: String,
    value: String,
}

#[derive(Debug, Tabled)]
struct RemoteOverlapDisplayRow<'a> {
    rank: usize,
    source: &'a str,
    ov4: usize,
    ov6: usize,
    covered4: usize,
    covered6: usize,
    covered_pct_local: String,
    stale: &'a str,
}

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
                apply_fully_covered_local,
            } => run_analyze_overlap_command(
                print_fully_covered_local,
                print_reduced_local,
                apply_fully_covered_local,
            ),
        },
        Command::Ban { target, asn } => run_ban_command(target.as_deref(), asn.as_deref()),
        Command::Unban { target, asn, yes } => {
            run_unban_command(target.as_deref(), asn.as_deref(), yes)
        }
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
    apply_fully_covered_local: bool,
) -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
    let config = load_config_from_file(&paths.config_file)?;
    let stale_after_secs = u64::from(config.remote.cache_stale_after_secs.get());
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
    let reduced_total = reduced.ipv4.len() + reduced.ipv6.len();
    let fully_covered_total = fully_covered.ipv4.len() + fully_covered.ipv6.len();

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

    print_overlap_summary(
        &local,
        &remote_union,
        union_overlap,
        OverlapSummaryData {
            remote_source_count: sources.remote_sources.len(),
            stale_source_count: stale_sources.len(),
            stale_after_secs,
            fully_covered_total,
            reduced_total,
        },
    );

    if !sources.remote_sources.is_empty() {
        let rows = build_remote_overlap_rows(&sources.remote_sources, &local);
        print_remote_overlap_rows(&rows, local.ipv4.len() + local.ipv6.len());
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

    if apply_fully_covered_local {
        let fully_covered_raw =
            fully_covered_local(&split_by_family(&sources.local_cidrs), &remote_union);
        let removed =
            apply_remove_fully_covered_entries(&paths.blocklist_file, &fully_covered_raw)?;
        println!();
        println!(
            "applied removal: removed_entries={} from {}",
            removed,
            paths.blocklist_file.display()
        );
        println!("changes take effect after running `sudo kidobo sync`");
    }

    Ok(())
}

fn apply_remove_fully_covered_entries(
    path: &std::path::Path,
    fully_covered: &crate::core::blocklist_analysis::FamilyReduction,
) -> Result<usize, KidoboError> {
    if !path.exists() {
        return Ok(0);
    }

    let contents = read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
        KidoboError::BlocklistRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    let mut remove_set = HashSet::<CanonicalCidr>::new();
    for cidr in &fully_covered.ipv4 {
        remove_set.insert(CanonicalCidr::V4(*cidr));
    }
    for cidr in &fully_covered.ipv6 {
        remove_set.insert(CanonicalCidr::V6(*cidr));
    }

    let mut removed = 0_usize;
    let mut kept_lines = Vec::new();
    for line in contents.lines() {
        let remove_line = line
            .split_whitespace()
            .next()
            .and_then(parse_ip_cidr_token)
            .is_some_and(|cidr| remove_set.contains(&cidr));
        if remove_line {
            removed += 1;
        } else {
            kept_lines.push(line.to_string());
        }
    }

    let mut output = kept_lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }

    fs::write(path, output).map_err(|err| KidoboError::BlocklistWrite {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;

    Ok(removed)
}

#[allow(clippy::print_stdout)]
fn print_overlap_summary(
    local: &crate::core::network::FamilyCidrs,
    remote_union: &crate::core::network::FamilyCidrs,
    union_overlap: crate::core::blocklist_analysis::OverlapCount,
    summary: OverlapSummaryData,
) {
    let local_total = local.ipv4.len() + local.ipv6.len();
    let overlapped_total = union_overlap.ipv4.overlapping + union_overlap.ipv6.overlapping;
    let covered_total = union_overlap.ipv4.fully_covered + union_overlap.ipv6.fully_covered;
    let overlapped_pct = percent(overlapped_total, local_total);
    let covered_pct = percent(covered_total, local_total);

    println!("analyze overlap (offline cache only)");
    println!();
    println!("summary:");
    let rows = vec![
        SummaryRow {
            metric: "local collapsed".to_string(),
            value: format!(
                "ipv4={} ipv6={} total={}",
                local.ipv4.len(),
                local.ipv6.len(),
                local.ipv4.len() + local.ipv6.len()
            ),
        },
        SummaryRow {
            metric: "remote cache sources".to_string(),
            value: format!(
                "total={} stale={} stale_after_secs={}",
                summary.remote_source_count, summary.stale_source_count, summary.stale_after_secs
            ),
        },
        SummaryRow {
            metric: "remote union".to_string(),
            value: format!(
                "ipv4={} ipv6={} total={}",
                remote_union.ipv4.len(),
                remote_union.ipv6.len(),
                remote_union.ipv4.len() + remote_union.ipv6.len()
            ),
        },
        SummaryRow {
            metric: "overlap with union".to_string(),
            value: format!(
                "ov4={} ov6={} covered4={} covered6={}",
                union_overlap.ipv4.overlapping,
                union_overlap.ipv6.overlapping,
                union_overlap.ipv4.fully_covered,
                union_overlap.ipv6.fully_covered
            ),
        },
        SummaryRow {
            metric: "reduction options".to_string(),
            value: format!(
                "remove_fully_covered={} reduced_local={}",
                summary.fully_covered_total, summary.reduced_total
            ),
        },
    ];

    let mut table = Table::new(rows);
    table.with(Style::modern());
    println!("{table}");

    println!("interpretation:");
    println!(
        "  {overlapped_total} of {local_total} local entries overlap remote cached sources ({overlapped_pct}%)."
    );
    println!(
        "  {covered_total} of {local_total} local entries are fully covered and removable ({covered_pct}%)."
    );
    println!(
        "  use `kidobo analyze overlap --print-fully-covered-local` to review exact removals."
    );
    println!(
        "  use `kidobo analyze overlap --print-reduced-local` to generate a local-minus-remote candidate set."
    );
}

fn build_remote_overlap_rows<'a>(
    remote_sources: &'a [crate::adapters::blocklist_analysis_sources::AnalysisRemoteSource],
    local: &crate::core::network::FamilyCidrs,
) -> Vec<RemoteOverlapRow<'a>> {
    let mut rows = Vec::with_capacity(remote_sources.len());
    for source in remote_sources {
        let source_family = collapse_by_family(&source.cidrs);
        let overlap = overlap_counts(local, &source_family);
        rows.push(RemoteOverlapRow {
            label: &source.label,
            ov4: overlap.ipv4.overlapping,
            ov6: overlap.ipv6.overlapping,
            covered4: overlap.ipv4.fully_covered,
            covered6: overlap.ipv6.fully_covered,
            stale: source.stale,
        });
    }

    rows.sort_by_key(|row| {
        let covered_total = row.covered4 + row.covered6;
        let overlap_total = row.ov4 + row.ov6;
        (
            Reverse(covered_total),
            Reverse(overlap_total),
            Reverse(row.stale),
            row.label,
        )
    });

    rows
}

#[allow(clippy::print_stdout)]
fn print_remote_overlap_rows(rows: &[RemoteOverlapRow<'_>], local_total: usize) {
    let displayed = rows
        .iter()
        .filter(|row| row.ov4 + row.ov6 + row.covered4 + row.covered6 > 0)
        .collect::<Vec<_>>();
    let hidden_zero_count = rows.len().saturating_sub(displayed.len());
    println!();
    println!("per-remote overlap:");
    println!("  sorted by covered then overlap");
    let display_rows = displayed
        .iter()
        .enumerate()
        .map(|(idx, row)| RemoteOverlapDisplayRow {
            rank: idx + 1,
            source: row.label,
            ov4: row.ov4,
            ov6: row.ov6,
            covered4: row.covered4,
            covered6: row.covered6,
            covered_pct_local: percent_str(row.covered4 + row.covered6, local_total),
            stale: if row.stale { "yes" } else { "no" },
        })
        .collect::<Vec<_>>();
    let mut table = Table::new(display_rows);
    table.with(Style::modern());
    println!("{table}");

    if hidden_zero_count > 0 {
        println!("omitted {hidden_zero_count} remote source(s) with zero overlap/coverage");
    }
}

fn percent(numerator: usize, denominator: usize) -> usize {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(100) / denominator
}

fn percent_str(numerator: usize, denominator: usize) -> String {
    format!("{}%", percent(numerator, denominator))
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
