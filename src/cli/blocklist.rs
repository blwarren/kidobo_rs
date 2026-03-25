mod plan;

use std::collections::{BTreeSet, HashSet};
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use log::{info, warn};

use crate::adapters::asn::{
    Bgpq4AsnPrefixResolver, delete_asn_cache_file, load_asn_prefixes_with_cache,
    normalize_asn_tokens,
};
use crate::adapters::blocklist_file::{
    BLOCKLIST_READ_LIMIT, BlocklistFile, ensure_blocklist_parent, write_blocklist_lines,
};
use crate::adapters::config::load_config_from_file;
use crate::adapters::config_edit::update_asn_bans;
use crate::adapters::limited_io::{read_to_string_with_limit, write_string_atomic};
use crate::adapters::lock::acquire_non_blocking;
use crate::adapters::path::{PathResolutionInput, resolve_paths};
use crate::core::blocklist::{
    BanClassification, classify_ban_targets, exact_match_indexes, plan_unban_many,
};
use crate::core::network::CanonicalCidr;
use crate::error::KidoboError;

use self::plan::{
    PartialMatch, UnbanPlan, apply_unban_plan, build_unban_plan, parse_blocklist_target,
};
#[cfg(test)]
use crate::adapters::blocklist_file::{
    BlocklistNormalizeResult, canonicalize_blocklist, normalize_local_blocklist,
    normalize_local_blocklist_with_fast_state,
};

const BLOCKLIST_TARGET_FILE_READ_LIMIT: usize = 2 * 1024 * 1024;

#[allow(clippy::print_stdout, clippy::print_stderr)]
pub fn run_ban_command(
    target: Option<&str>,
    file: Option<&Path>,
    asn: Option<&[String]>,
) -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
    let _lock = acquire_non_blocking(&paths.lock_file)?;
    if let Some(asn_tokens) = asn {
        return run_ban_asn_command(
            &paths.config_file,
            &paths.blocklist_file,
            &paths.cache_dir,
            asn_tokens,
        );
    }

    if let Some(file) = file {
        return run_ban_file_command(&paths.blocklist_file, file);
    }

    let Some(target) = target else {
        return Err(KidoboError::BlocklistTargetParse {
            input: String::new(),
        });
    };
    let outcome = ban_target_in_file(&paths.blocklist_file, target)?;

    match outcome {
        BanOutcome::Added(value) => println!("added blocklist entry {value}"),
        BanOutcome::AlreadyPresent(value) => println!("blocklist already contains {value}"),
    }

    println!("changes take effect after running `sudo kidobo sync`");

    Ok(())
}

#[derive(Debug, PartialEq)]
pub enum BanOutcome {
    Added(String),
    AlreadyPresent(String),
}

impl From<BanClassification> for BanOutcome {
    fn from(value: BanClassification) -> Self {
        match value {
            BanClassification::Added(cidr) => Self::Added(cidr.to_string()),
            BanClassification::AlreadyPresent(cidr) => Self::AlreadyPresent(cidr.to_string()),
        }
    }
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
pub fn run_unban_command(
    target: Option<&str>,
    file: Option<&Path>,
    asn: Option<&[String]>,
    yes: bool,
) -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
    if let Some(asn_tokens) = asn {
        let _lock = acquire_non_blocking(&paths.lock_file)?;
        return run_unban_asn_command(&paths.config_file, &paths.cache_dir, asn_tokens);
    }

    if let Some(file) = file {
        return run_unban_file_command(&paths.blocklist_file, &paths.lock_file, file, yes);
    }

    let Some(target) = target else {
        return Err(KidoboError::BlocklistTargetParse {
            input: String::new(),
        });
    };
    run_unban_target_command(&paths.blocklist_file, &paths.lock_file, target, yes)
}

#[derive(Debug)]
struct FileUnbanRequest {
    requested_target_count: usize,
    plan: UnbanPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnbanPreview {
    target: String,
    exact_entries: Vec<String>,
    partial_entries: Vec<String>,
}

impl UnbanPreview {
    fn from_plan(plan: &UnbanPlan) -> Self {
        Self {
            target: plan.target.clone(),
            exact_entries: plan_entry_strings(&plan.blocklist, &plan.exact_indexes),
            partial_entries: partial_entry_strings(&plan.partial_matches),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileUnbanPreview {
    requested_target_count: usize,
    exact_entries: Vec<String>,
    partial_entries: Vec<String>,
}

impl FileUnbanPreview {
    fn from_request(request: &FileUnbanRequest) -> Self {
        Self {
            requested_target_count: request.requested_target_count,
            exact_entries: plan_entry_strings(&request.plan.blocklist, &request.plan.exact_indexes),
            partial_entries: partial_entry_strings(&request.plan.partial_matches),
        }
    }
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn run_ban_file_command(blocklist_path: &Path, target_file: &Path) -> Result<(), KidoboError> {
    let target_lines = read_blocklist_target_lines(target_file)?;
    let targets = parse_blocklist_targets_or_report(&target_lines)?;

    if targets.is_empty() {
        println!("no blocklist targets loaded from file");
        return Ok(());
    }

    let outcomes = ban_targets_in_file(blocklist_path, &targets)?;
    for outcome in outcomes {
        match outcome {
            BanOutcome::Added(value) => println!("added blocklist entry {value}"),
            BanOutcome::AlreadyPresent(value) => println!("blocklist already contains {value}"),
        }
    }

    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

#[allow(clippy::print_stdout)]
fn run_unban_file_command(
    blocklist_path: &Path,
    lock_path: &Path,
    target_file: &Path,
    yes: bool,
) -> Result<(), KidoboError> {
    let target_lines = read_blocklist_target_lines(target_file)?;
    let targets = parse_blocklist_targets_or_report(&target_lines)?;

    if targets.is_empty() {
        println!("no blocklist targets loaded from file");
        return Ok(());
    }

    let preview_request = build_unban_file_request(blocklist_path, &targets)?;
    let preview = FileUnbanPreview::from_request(&preview_request);
    let remove_partial = confirm_partial_matches(
        "file targets also match the following blocklist entries:",
        &preview_request.plan.partial_matches,
        yes,
    )?;

    let _lock = acquire_non_blocking(lock_path)?;
    let mut request = build_unban_file_request(blocklist_path, &targets)?;
    if FileUnbanPreview::from_request(&request) != preview {
        return Err(KidoboError::BlocklistChanged);
    }
    request.plan.remove_partial = remove_partial;

    if request.plan.total_removal() == 0 {
        if request.plan.partial_matches.is_empty() {
            println!(
                "no blocklist entries matched {} file target(s)",
                request.requested_target_count
            );
        } else {
            println!(
                "no blocklist entries were removed for {} file target(s)",
                request.requested_target_count
            );
        }
        return Ok(());
    }

    let result = apply_unban_plan(blocklist_path, &request.plan)?;
    println!(
        "removed {} blocklist entries for {} file target(s)",
        result.total(),
        request.requested_target_count
    );
    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

#[allow(clippy::print_stdout)]
fn run_unban_target_command(
    blocklist_path: &Path,
    lock_path: &Path,
    target: &str,
    yes: bool,
) -> Result<(), KidoboError> {
    let preview_plan = build_unban_plan(blocklist_path, target)?;
    let preview = UnbanPreview::from_plan(&preview_plan);
    let remove_partial = confirm_partial_matches(
        &format!(
            "{} also matches the following blocklist entries:",
            preview_plan.target
        ),
        &preview_plan.partial_matches,
        yes,
    )?;

    let _lock = acquire_non_blocking(lock_path)?;
    let mut plan = build_unban_plan(blocklist_path, target)?;
    if UnbanPreview::from_plan(&plan) != preview {
        return Err(KidoboError::BlocklistChanged);
    }
    plan.remove_partial = remove_partial;

    if plan.total_removal() == 0 {
        println!("no blocklist entries match {}", plan.target);
        return Ok(());
    }

    let result = apply_unban_plan(blocklist_path, &plan)?;
    println!(
        "removed {} blocklist entries for {}",
        result.total(),
        plan.target
    );
    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

#[allow(clippy::print_stdout)]
fn run_ban_asn_command(
    config_path: &Path,
    blocklist_path: &Path,
    cache_dir: &Path,
    asn_tokens: &[String],
) -> Result<(), KidoboError> {
    let requested_asns = normalize_asn_tokens(asn_tokens)?;
    let config = load_config_from_file(config_path)?;
    let stale_after = Duration::from_secs(u64::from(config.asn.cache_stale_after_secs.get()));
    let asn_cache_dir = cache_dir.join("asn");
    let resolver = Bgpq4AsnPrefixResolver::with_default_timeout();

    let mut resolved_prefixes = Vec::new();
    for asn in &requested_asns {
        let cached = load_asn_prefixes_with_cache(*asn, &asn_cache_dir, stale_after, &resolver)?;
        if cached.stale {
            warn!("ASN cache stale fallback used for AS{asn}");
        }
        resolved_prefixes.extend(cached.prefixes);
    }
    resolved_prefixes.sort_unstable();
    resolved_prefixes.dedup();

    let update = update_asn_bans(config_path, &requested_asns, &[])?;
    let removed_dups = remove_exact_blocklist_duplicates(blocklist_path, &resolved_prefixes)?;

    println!(
        "added {} ASN ban(s): {}",
        update.added.len(),
        format_asn_list(&update.added)
    );
    if removed_dups > 0 {
        println!("removed {removed_dups} duplicate IP/CIDR entry(ies) from local blocklist");
    }
    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

#[allow(clippy::print_stdout)]
fn run_unban_asn_command(
    config_path: &Path,
    cache_dir: &Path,
    asn_tokens: &[String],
) -> Result<(), KidoboError> {
    let requested_asns = normalize_asn_tokens(asn_tokens)?;
    let update = update_asn_bans(config_path, &[], &requested_asns)?;
    let asn_cache_dir = cache_dir.join("asn");
    let mut deleted_cache_count = 0_usize;
    for asn in &requested_asns {
        if delete_asn_cache_file(*asn, &asn_cache_dir)? {
            deleted_cache_count += 1;
        }
    }

    println!(
        "removed {} ASN ban(s): {}",
        update.removed.len(),
        format_asn_list(&update.removed)
    );
    println!("deleted {deleted_cache_count} ASN cache file(s)");
    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

fn format_asn_list(asns: &[u32]) -> String {
    asns.iter()
        .map(|asn| format!("AS{asn}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn remove_exact_blocklist_duplicates(
    path: &Path,
    duplicates: &[CanonicalCidr],
) -> Result<usize, KidoboError> {
    if duplicates.is_empty() || !path.exists() {
        return Ok(0);
    }
    let blocklist = BlocklistFile::load(path)?;
    let line_canonicals = blocklist
        .lines
        .iter()
        .map(|line| line.canonical)
        .collect::<Vec<_>>();
    let removal_indexes = exact_match_indexes(&line_canonicals, duplicates)
        .into_iter()
        .collect::<HashSet<_>>();
    let kept_lines = blocklist
        .lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            if removal_indexes.contains(&idx) {
                None
            } else {
                Some(line.original.as_str())
            }
        })
        .collect::<Vec<_>>();

    let removed = blocklist.lines.len().saturating_sub(kept_lines.len());
    if removed > 0 {
        write_blocklist_lines(path, &kept_lines)?;
        info!("removed duplicate local blocklist entries covered by ASN bans: removed={removed}");
    }
    Ok(removed)
}

fn ban_targets_in_file(
    path: &Path,
    targets: &[CanonicalCidr],
) -> Result<Vec<BanOutcome>, KidoboError> {
    let blocklist = BlocklistFile::load(path)?;
    let existing = blocklist
        .lines
        .iter()
        .filter_map(|line| line.canonical)
        .collect::<Vec<_>>();
    let classifications = classify_ban_targets(&existing, targets);
    let mut appended_entries = Vec::new();
    let mut outcomes = Vec::with_capacity(classifications.len());

    for classification in classifications {
        if let BanClassification::Added(cidr) = classification {
            appended_entries.push(cidr.to_string());
        }
        outcomes.push(BanOutcome::from(classification));
    }

    if !appended_entries.is_empty() {
        ensure_blocklist_parent(path)?;
        append_blocklist_entries(
            path,
            &appended_entries,
            blocklist.has_content,
            blocklist.trailing_newline,
        )?;
    }

    Ok(outcomes)
}

fn ban_target_in_file(path: &Path, input: &str) -> Result<BanOutcome, KidoboError> {
    let canonical = parse_blocklist_target(input)?;
    let blocklist = BlocklistFile::load(path)?;
    let existing = blocklist
        .lines
        .iter()
        .filter_map(|line| line.canonical)
        .collect::<Vec<_>>();
    let Some(classification) = classify_ban_targets(&existing, &[canonical])
        .into_iter()
        .next()
    else {
        unreachable!("single target must produce a classification");
    };
    let outcome = BanOutcome::from(classification);

    if matches!(outcome, BanOutcome::Added(_)) {
        let canonical_str = canonical.to_string();
        ensure_blocklist_parent(path)?;
        append_blocklist_entries(
            path,
            &[canonical_str.as_str()],
            blocklist.has_content,
            blocklist.trailing_newline,
        )?;
    }

    Ok(outcome)
}

fn append_blocklist_entries<S: AsRef<str>>(
    path: &Path,
    entries: &[S],
    has_content: bool,
    trailing_newline: bool,
) -> Result<(), KidoboError> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut contents = if path.exists() {
        read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
            KidoboError::BlocklistRead {
                path: path.to_path_buf(),
                reason: err.to_string(),
            }
        })?
    } else {
        String::new()
    };
    if has_content && !trailing_newline {
        contents.push('\n');
    }
    for entry in entries {
        contents.push_str(entry.as_ref());
        contents.push('\n');
    }

    write_string_atomic(path, &contents).map_err(|err| KidoboError::BlocklistWrite {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

fn read_blocklist_target_lines(path: &Path) -> Result<Vec<String>, KidoboError> {
    let contents =
        read_to_string_with_limit(path, BLOCKLIST_TARGET_FILE_READ_LIMIT).map_err(|err| {
            KidoboError::BlocklistTargetFileRead {
                path: path.to_path_buf(),
                reason: err.to_string(),
            }
        })?;

    Ok(contents.lines().map(ToString::to_string).collect())
}

#[allow(clippy::print_stderr)]
fn parse_blocklist_targets_or_report(inputs: &[String]) -> Result<Vec<CanonicalCidr>, KidoboError> {
    let mut targets = Vec::with_capacity(inputs.len());
    let mut invalid_inputs = Vec::new();

    for input in inputs {
        match parse_blocklist_target(input) {
            Ok(target) => targets.push(target),
            Err(_) => invalid_inputs.push(input.clone()),
        }
    }

    for invalid in &invalid_inputs {
        eprintln!("invalid target: {invalid}");
    }

    if invalid_inputs.is_empty() {
        Ok(targets)
    } else {
        Err(KidoboError::BlocklistInvalidTargets {
            count: invalid_inputs.len(),
        })
    }
}

fn build_unban_file_request(
    path: &Path,
    targets: &[CanonicalCidr],
) -> Result<FileUnbanRequest, KidoboError> {
    let blocklist = BlocklistFile::load(path)?;
    let line_canonicals = blocklist
        .lines
        .iter()
        .map(|line| line.canonical)
        .collect::<Vec<_>>();
    let index_plan = plan_unban_many(&line_canonicals, targets);
    let partial_matches = partial_matches_for_indexes(&blocklist, &index_plan.partial_indexes);

    Ok(FileUnbanRequest {
        requested_target_count: targets.len(),
        plan: UnbanPlan {
            target: format!("{} file target(s)", targets.len()),
            blocklist,
            exact_indexes: index_plan.exact_indexes,
            partial_matches,
            remove_partial: false,
        },
    })
}

fn partial_matches_for_indexes(blocklist: &BlocklistFile, indexes: &[usize]) -> Vec<PartialMatch> {
    let partial_indexes = indexes.iter().copied().collect::<BTreeSet<_>>();

    blocklist
        .lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            if !partial_indexes.contains(&index) {
                return None;
            }

            line.canonical.map(|canonical| PartialMatch {
                index,
                entry: canonical.to_string(),
            })
        })
        .collect()
}

fn plan_entry_strings(blocklist: &BlocklistFile, indexes: &[usize]) -> Vec<String> {
    let mut entries = indexes
        .iter()
        .filter_map(|idx| blocklist.lines.get(*idx))
        .filter_map(|line| line.canonical.map(|canonical| canonical.to_string()))
        .collect::<Vec<_>>();
    entries.sort_unstable();
    entries
}

fn partial_entry_strings(partial_matches: &[PartialMatch]) -> Vec<String> {
    let mut entries = partial_matches
        .iter()
        .map(|partial| partial.entry.clone())
        .collect::<Vec<_>>();
    entries.sort_unstable();
    entries
}

#[allow(clippy::print_stdout)]
fn prompt_confirmation() -> Result<bool, KidoboError> {
    print!("Remove these entries as well? [y/N]: ");
    io::stdout()
        .flush()
        .map_err(|err| KidoboError::BlocklistPrompt {
            reason: err.to_string(),
        })?;

    let mut buffer = String::new();
    io::stdin()
        .read_line(&mut buffer)
        .map_err(|err| KidoboError::BlocklistPrompt {
            reason: err.to_string(),
        })?;

    let response = buffer.trim().to_ascii_lowercase();
    Ok(matches!(response.as_str(), "y" | "yes"))
}

#[allow(clippy::print_stdout)]
fn confirm_partial_matches(
    heading: &str,
    partial_matches: &[PartialMatch],
    yes: bool,
) -> Result<bool, KidoboError> {
    if partial_matches.is_empty() {
        return Ok(false);
    }

    println!("{heading}");
    for partial in partial_matches {
        println!("  - {}", partial.entry);
    }

    if yes {
        println!("auto-approving removal of partial matches");
        Ok(true)
    } else {
        prompt_confirmation()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use crate::core::network::{
        CanonicalCidr, ipv4_to_interval, ipv6_to_interval, parse_ip_cidr_non_strict,
    };

    use super::{
        BLOCKLIST_READ_LIMIT, BLOCKLIST_TARGET_FILE_READ_LIMIT, BanOutcome, BlocklistFile,
        BlocklistNormalizeResult, KidoboError, append_blocklist_entries, apply_unban_plan,
        ban_target_in_file, ban_targets_in_file, build_unban_file_request, build_unban_plan,
        canonicalize_blocklist, ensure_blocklist_parent, normalize_local_blocklist,
        normalize_local_blocklist_with_fast_state, parse_blocklist_target,
        parse_blocklist_targets_or_report, read_blocklist_target_lines,
        remove_exact_blocklist_duplicates, write_blocklist_lines,
    };
    use crate::adapters::limited_io::read_to_string_with_limit;

    fn write_temp_file(temp: &TempDir, contents: &str) -> PathBuf {
        let path = temp.path().join("blocklist.txt");
        fs::write(&path, contents).expect("write temp");
        path
    }

    #[test]
    fn ban_appends_entry_when_missing() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");

        let outcome = ban_target_in_file(&path, "203.0.113.0/24").expect("ban");
        assert_eq!(outcome, BanOutcome::Added("203.0.113.0/24".into()));

        let contents = read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT).expect("read");
        assert_eq!(contents, "203.0.113.0/24\n");
    }

    #[test]
    fn ban_is_idempotent() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(&path, "203.0.113.0/24\n").expect("write");

        let outcome = ban_target_in_file(&path, "203.0.113.0/24").expect("ban");
        assert_eq!(outcome, BanOutcome::AlreadyPresent("203.0.113.0/24".into()));

        let contents = read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT).expect("read");
        assert_eq!(contents, "203.0.113.0/24\n");
    }

    #[test]
    fn ban_targets_in_file_preserves_order_and_dedups_existing_entries() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(&path, "198.51.100.0/24").expect("write");
        let targets = vec![
            parse_ip_cidr_non_strict("203.0.113.7").expect("parse first"),
            parse_ip_cidr_non_strict("198.51.100.0/24").expect("parse second"),
            parse_ip_cidr_non_strict("203.0.113.7").expect("parse third"),
        ];

        let outcomes = ban_targets_in_file(&path, &targets).expect("ban file targets");

        assert_eq!(
            outcomes,
            vec![
                BanOutcome::Added("203.0.113.7/32".into()),
                BanOutcome::AlreadyPresent("198.51.100.0/24".into()),
                BanOutcome::AlreadyPresent("203.0.113.7/32".into()),
            ]
        );
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "198.51.100.0/24\n203.0.113.7/32\n"
        );
    }

    #[test]
    fn unban_removes_exact_entry() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(&path, "198.51.100.0/24\n203.0.113.0/24\n").expect("write");

        let plan = build_unban_plan(&path, "198.51.100.0/24").expect("plan");
        let result = apply_unban_plan(&path, &plan).expect("apply");

        assert_eq!(result.total(), 1);
        let contents = read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT).expect("read");
        assert_eq!(contents, "203.0.113.0/24\n");
        assert_eq!(plan.partial_matches.len(), 0);
        assert_eq!(plan.exact_indexes.len(), 1);
    }

    #[test]
    fn unban_partial_requires_confirmation() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(&path, "203.0.113.0/24\n").expect("write");

        let mut plan = build_unban_plan(&path, "203.0.113.7").expect("plan");
        assert_eq!(plan.partial_matches.len(), 1);
        plan.remove_partial = true;
        let result = apply_unban_plan(&path, &plan).expect("apply");

        assert_eq!(result.removed_partial, 1);
        let contents = read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT).expect("read");
        assert!(contents.is_empty());
    }

    fn canonical_contains_local(entry: &CanonicalCidr, target: &CanonicalCidr) -> bool {
        match (entry, target) {
            (CanonicalCidr::V4(entry_cidr), CanonicalCidr::V4(target_cidr)) => {
                let entry_interval = ipv4_to_interval(*entry_cidr);
                let target_interval = ipv4_to_interval(*target_cidr);
                entry_interval.start <= target_interval.start
                    && entry_interval.end >= target_interval.end
            }
            (CanonicalCidr::V6(entry_cidr), CanonicalCidr::V6(target_cidr)) => {
                let entry_interval = ipv6_to_interval(*entry_cidr);
                let target_interval = ipv6_to_interval(*target_cidr);
                entry_interval.start <= target_interval.start
                    && entry_interval.end >= target_interval.end
            }
            _ => false,
        }
    }

    #[test]
    fn canonical_contains_detects_ipv4_and_ipv6_crop() {
        let supernet_v4 = parse_ip_cidr_non_strict("203.0.113.0/24").expect("parse");
        let host_v4 = parse_ip_cidr_non_strict("203.0.113.7").expect("parse");
        assert!(canonical_contains_local(&supernet_v4, &host_v4));

        let supernet_v6 = parse_ip_cidr_non_strict("2001:db8::/64").expect("parse");
        let host_v6 = parse_ip_cidr_non_strict("2001:db8::1").expect("parse");
        assert!(canonical_contains_local(&supernet_v6, &host_v6));

        let mismatch = parse_ip_cidr_non_strict("203.0.113.7").expect("parse");
        let mismatch_v6 = parse_ip_cidr_non_strict("2001:db8::1").expect("parse");
        assert!(!canonical_contains_local(&mismatch, &mismatch_v6));
    }

    #[test]
    fn parse_blocklist_target_errors_on_invalid_input() {
        let err = parse_blocklist_target("not-an-ip").expect_err("expected error");
        if let KidoboError::BlocklistTargetParse { input } = err {
            assert_eq!(input, "not-an-ip");
        } else {
            panic!("unexpected error variant");
        }
    }

    #[test]
    fn blocklist_file_loads_metadata_and_contains_entries() {
        let temp = TempDir::new().expect("tempdir");
        let path = write_temp_file(&temp, "203.0.113.0/24\n\n# comment\n2001:db8::/64\n");
        let blocklist = BlocklistFile::load(&path).expect("load");

        assert_eq!(blocklist.lines.len(), 4);
        let cidr = parse_ip_cidr_non_strict("2001:db8::/64").expect("parse");
        assert!(blocklist.contains_canonical(cidr));
        assert!(blocklist.has_content);
        assert!(blocklist.trailing_newline);
    }

    #[test]
    fn build_plan_reports_partial_for_overlapping_entry() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(&path, "174.129.101.247/32\n").expect("write");

        let plan = build_unban_plan(&path, "174.129.101.0/24").expect("plan");
        assert!(plan.exact_indexes.is_empty());
        assert_eq!(plan.partial_matches.len(), 1);
    }

    #[test]
    fn build_unban_file_request_excludes_exact_entries_from_partial_prompt() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(&path, "203.0.113.0/24\n198.51.100.0/24\n").expect("write");
        let targets = vec![
            parse_ip_cidr_non_strict("203.0.113.0/24").expect("parse exact"),
            parse_ip_cidr_non_strict("203.0.113.7").expect("parse partial"),
            parse_ip_cidr_non_strict("198.51.100.7").expect("parse second partial"),
        ];

        let request = build_unban_file_request(&path, &targets).expect("build file request");

        assert_eq!(request.requested_target_count, 3);
        assert_eq!(request.plan.exact_indexes, vec![0]);
        assert_eq!(request.plan.partial_matches.len(), 1);
        assert_eq!(request.plan.partial_matches[0].entry, "198.51.100.0/24");
    }

    #[test]
    fn append_blocklist_entries_handle_newline_states() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");

        append_blocklist_entries(&path, &["203.0.113.0/24"], false, false).expect("append");
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "203.0.113.0/24\n"
        );

        fs::write(&path, "203.0.113.0/24").expect("write no newline");
        append_blocklist_entries(&path, &["198.51.100.0/24"], true, false).expect("append2");
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "203.0.113.0/24\n198.51.100.0/24\n"
        );
    }

    #[test]
    fn read_blocklist_target_lines_reports_missing_file() {
        let temp = TempDir::new().expect("tempdir");
        let missing = temp.path().join("targets.txt");

        let err = read_blocklist_target_lines(&missing).expect_err("missing file must fail");
        assert!(matches!(
            err,
            KidoboError::BlocklistTargetFileRead { path, .. } if path == missing
        ));
    }

    #[test]
    fn read_blocklist_target_lines_rejects_oversized_input() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("targets.txt");
        fs::write(&path, "1".repeat(BLOCKLIST_TARGET_FILE_READ_LIMIT + 1)).expect("write");

        let err = read_blocklist_target_lines(&path).expect_err("oversized file must fail");
        assert!(matches!(
            err,
            KidoboError::BlocklistTargetFileRead {
                path: err_path,
                ..
            } if err_path == path
        ));
    }

    #[test]
    fn parse_blocklist_targets_or_report_collects_all_invalid_inputs() {
        let err = parse_blocklist_targets_or_report(&[
            "203.0.113.7".to_string(),
            "not-an-ip".to_string(),
            String::new(),
        ])
        .expect_err("invalid inputs must fail");

        assert!(matches!(
            err,
            KidoboError::BlocklistInvalidTargets { count } if count == 2
        ));
    }

    #[test]
    fn write_blocklist_lines_creates_newline_and_can_clear() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");

        write_blocklist_lines(&path, &["a", "b"]).expect("write");
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "a\nb\n"
        );

        write_blocklist_lines(&path, &[] as &[&str]).expect("write empty");
        assert!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .is_empty()
        );
    }

    #[test]
    fn normalize_local_blocklist_preserves_only_header_comments_and_canonicalizes_entries() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(
            &path,
            "# top comment \n203.0.113.7\n# dropped later comment\n203.0.113.0/24\n2001:db8::/64\n2001:db8::/64\n",
        )
        .expect("write");

        normalize_local_blocklist(&path).expect("normalize");

        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "# top comment\n\n203.0.113.0/24\n2001:db8::/64\n"
        );
    }

    #[test]
    fn normalize_local_blocklist_preserves_multiline_header_comments() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(
            &path,
            "# top comment\n# second comment\n\n203.0.113.7\n# dropped later comment\n",
        )
        .expect("write");

        normalize_local_blocklist(&path).expect("normalize");

        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "# top comment\n# second comment\n\n203.0.113.7/32\n"
        );
    }

    #[test]
    fn normalize_with_fast_state_skips_when_unchanged() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        let state_path = temp.path().join("cache/blocklist-normalize.fast-state");
        fs::write(&path, "203.0.113.7\n203.0.113.0/24\n").expect("write");

        let first =
            normalize_local_blocklist_with_fast_state(&path, &state_path).expect("first normalize");
        assert_eq!(first, BlocklistNormalizeResult::Checked);

        let second = normalize_local_blocklist_with_fast_state(&path, &state_path)
            .expect("second normalize should skip");
        assert_eq!(second, BlocklistNormalizeResult::SkippedUnchanged);
    }

    #[test]
    fn normalize_with_fast_state_rechecks_when_fast_state_is_invalid() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        let state_path = temp.path().join("cache/blocklist-normalize.fast-state");
        fs::write(&path, "203.0.113.7\n").expect("write");
        fs::create_dir_all(state_path.parent().expect("parent")).expect("mkdir cache");
        fs::write(&state_path, "not valid fast state\n").expect("write state");

        let result = normalize_local_blocklist_with_fast_state(&path, &state_path)
            .expect("normalize should recheck");
        assert_eq!(result, BlocklistNormalizeResult::Checked);
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "203.0.113.7/32\n"
        );
    }

    #[test]
    fn normalize_with_fast_state_rechecks_after_blocklist_change() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        let state_path = temp.path().join("cache/blocklist-normalize.fast-state");
        fs::write(&path, "203.0.113.7\n203.0.113.0/24\n").expect("write");

        normalize_local_blocklist_with_fast_state(&path, &state_path).expect("first normalize");
        fs::write(&path, "198.51.100.7\n").expect("rewrite");

        let second = normalize_local_blocklist_with_fast_state(&path, &state_path)
            .expect("second normalize should recheck");
        assert_eq!(second, BlocklistNormalizeResult::Checked);
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "198.51.100.7/32\n"
        );
    }

    #[test]
    fn normalize_with_fast_state_returns_missing_when_blocklist_absent() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("missing.txt");
        let state_path = temp.path().join("cache/blocklist-normalize.fast-state");

        let result =
            normalize_local_blocklist_with_fast_state(&path, &state_path).expect("normalize");
        assert_eq!(result, BlocklistNormalizeResult::MissingBlocklist);
        assert!(!state_path.exists());
    }

    #[test]
    fn ensure_blocklist_parent_creates_directories_recursively() {
        let temp = TempDir::new().expect("tempdir");
        let nested = temp.path().join("nested/deeper/blocklist.txt");
        ensure_blocklist_parent(&nested).expect("ensure");
        assert!(nested.parent().unwrap().exists());
    }

    #[test]
    fn build_plan_with_partial_matches_respects_remove_partial_flag() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(&path, "203.0.113.0/24\n10.0.0.0/24\n").expect("write");

        let mut plan = build_unban_plan(&path, "203.0.113.7").expect("plan");
        assert!(plan.exact_indexes.is_empty());
        assert_eq!(plan.partial_matches.len(), 1);
        assert_eq!(plan.total_removal(), 0);

        let result = apply_unban_plan(&path, &plan).expect("apply_no_change");
        assert_eq!(result.total(), 0);
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "203.0.113.0/24\n10.0.0.0/24\n"
        );

        plan.remove_partial = true;
        let removal = apply_unban_plan(&path, &plan).expect("apply_remove");
        assert_eq!(removal.removed_partial, 1);
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "10.0.0.0/24\n"
        );
    }

    #[test]
    fn remove_exact_blocklist_duplicates_keeps_non_exact_entries() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(&path, "203.0.113.0/24\n203.0.113.7\n").expect("write");

        let duplicates = vec![parse_ip_cidr_non_strict("203.0.113.0/24").expect("cidr")];
        let removed = remove_exact_blocklist_duplicates(&path, &duplicates).expect("remove");
        assert_eq!(removed, 1);
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "203.0.113.7\n"
        );
    }

    #[test]
    fn remove_exact_blocklist_duplicates_short_circuits_for_missing_or_empty_input() {
        let temp = TempDir::new().expect("tempdir");
        let missing = temp.path().join("missing.txt");
        let removed = remove_exact_blocklist_duplicates(&missing, &[]).expect("remove");
        assert_eq!(removed, 0);
    }

    #[test]
    fn parse_blocklist_target_trims_whitespace_and_canonicalizes_hosts() {
        let parsed = parse_blocklist_target(" 203.0.113.7 ").expect("parse");
        assert_eq!(parsed.to_string(), "203.0.113.7/32");
    }

    #[test]
    fn canonicalize_blocklist_trims_header_trailing_blank_when_no_entries() {
        let normalized = canonicalize_blocklist("# header\n\n");
        assert_eq!(normalized, "# header\n");
    }
}
