use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crate::adapters::limited_io::read_to_string_with_limit;
use crate::adapters::path::{PathResolutionInput, resolve_paths};
use crate::core::network::{
    CanonicalCidr, IntervalU32, IntervalU128, collapse_ipv4, collapse_ipv6, ipv4_to_interval,
    ipv6_to_interval, parse_ip_cidr_non_strict, split_by_family,
};
use crate::error::KidoboError;

const BLOCKLIST_READ_LIMIT: usize = 16 * 1024 * 1024;

#[allow(clippy::print_stdout, clippy::print_stderr)]
pub fn run_ban_command(target: &str) -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
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

#[allow(clippy::print_stdout, clippy::print_stderr)]
pub fn run_unban_command(target: &str, yes: bool) -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
    let mut plan = build_unban_plan(&paths.blocklist_file, target)?;

    if !plan.partial_matches.is_empty() {
        println!(
            "{} also matches the following blocklist entries:",
            plan.target
        );
        for partial in &plan.partial_matches {
            println!("  - {}", partial.entry);
        }

        plan.remove_partial = if yes {
            println!("auto-approving removal of partial matches");
            true
        } else {
            prompt_confirmation()?
        };
    }

    if plan.total_removal() == 0 {
        println!("no blocklist entries match {}", plan.target);
        return Ok(());
    }

    let result = apply_unban_plan(&paths.blocklist_file, &plan)?;
    println!(
        "removed {} blocklist entries for {}",
        result.total(),
        plan.target
    );
    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

fn ban_target_in_file(path: &Path, input: &str) -> Result<BanOutcome, KidoboError> {
    let canonical = parse_blocklist_target(input)?;
    let blocklist = BlocklistFile::load(path)?;
    let canonical_str = canonical.to_string();

    if blocklist.contains(&canonical_str) {
        return Ok(BanOutcome::AlreadyPresent(canonical_str));
    }

    ensure_blocklist_parent(path)?;
    append_blocklist_entry(
        path,
        &canonical_str,
        blocklist.has_content,
        blocklist.trailing_newline,
    )?;

    Ok(BanOutcome::Added(canonical_str))
}

fn build_unban_plan(path: &Path, input: &str) -> Result<UnbanPlan, KidoboError> {
    let canonical = parse_blocklist_target(input)?;
    let blocklist = BlocklistFile::load(path)?;
    let mut exact_indexes = Vec::new();
    let mut partial_matches = Vec::new();

    for (idx, line) in blocklist.lines.iter().enumerate() {
        if let Some(entry) = &line.canonical {
            if entry == &canonical {
                exact_indexes.push(idx);
            } else if canonical_overlaps(entry, &canonical) {
                partial_matches.push(PartialMatch {
                    index: idx,
                    entry: entry.to_string(),
                });
            }
        }
    }

    Ok(UnbanPlan {
        target: canonical.to_string(),
        blocklist,
        exact_indexes,
        partial_matches,
        remove_partial: false,
    })
}

fn apply_unban_plan(path: &Path, plan: &UnbanPlan) -> Result<UnbanResult, KidoboError> {
    let mut removal_indexes: HashSet<usize> = plan.exact_indexes.iter().copied().collect();
    if plan.remove_partial {
        for partial in &plan.partial_matches {
            removal_indexes.insert(partial.index);
        }
    }

    if removal_indexes.is_empty() {
        return Ok(UnbanResult {
            removed_exact: 0,
            removed_partial: 0,
        });
    }

    let kept_lines: Vec<String> = plan
        .blocklist
        .lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            if removal_indexes.contains(&idx) {
                None
            } else {
                Some(line.original.clone())
            }
        })
        .collect();

    write_blocklist_lines(path, &kept_lines)?;

    let removed_partial = if plan.remove_partial {
        plan.partial_matches.len()
    } else {
        0
    };

    Ok(UnbanResult {
        removed_exact: plan.exact_indexes.len(),
        removed_partial,
    })
}

fn write_blocklist_lines(path: &Path, lines: &[String]) -> Result<(), KidoboError> {
    let mut contents = lines.join("\n");
    if !contents.is_empty() {
        contents.push('\n');
    }

    fs::write(path, contents).map_err(|err| KidoboError::BlocklistWrite {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

fn append_blocklist_entry(
    path: &Path,
    entry: &str,
    has_content: bool,
    trailing_newline: bool,
) -> Result<(), KidoboError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| KidoboError::BlocklistWrite {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;

    if has_content && !trailing_newline {
        file.write_all(b"\n")
            .map_err(|err| KidoboError::BlocklistWrite {
                path: path.to_path_buf(),
                reason: err.to_string(),
            })?;
    }

    writeln!(file, "{entry}").map_err(|err| KidoboError::BlocklistWrite {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

fn ensure_blocklist_parent(path: &Path) -> Result<(), KidoboError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| KidoboError::BlocklistWrite {
            path: parent.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    Ok(())
}

pub fn normalize_local_blocklist(path: &Path) -> Result<(), KidoboError> {
    if !path.exists() {
        return Ok(());
    }

    let original = read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
        KidoboError::BlocklistRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    let normalized = canonicalize_blocklist(&original);

    if normalized != original {
        fs::write(path, normalized).map_err(|err| KidoboError::BlocklistWrite {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    Ok(())
}

fn parse_blocklist_target(input: &str) -> Result<CanonicalCidr, KidoboError> {
    let token = input.trim();
    parse_ip_cidr_non_strict(token).ok_or_else(|| KidoboError::BlocklistTargetParse {
        input: input.to_string(),
    })
}
fn canonical_overlaps(entry: &CanonicalCidr, target: &CanonicalCidr) -> bool {
    match (entry, target) {
        (CanonicalCidr::V4(entry_cidr), CanonicalCidr::V4(target_cidr)) => intervals_overlap_u32(
            ipv4_to_interval(*entry_cidr),
            ipv4_to_interval(*target_cidr),
        ),
        (CanonicalCidr::V6(entry_cidr), CanonicalCidr::V6(target_cidr)) => intervals_overlap_u128(
            ipv6_to_interval(*entry_cidr),
            ipv6_to_interval(*target_cidr),
        ),
        _ => false,
    }
}

fn intervals_overlap_u32(a: IntervalU32, b: IntervalU32) -> bool {
    a.start <= b.end && b.start <= a.end
}

fn intervals_overlap_u128(a: IntervalU128, b: IntervalU128) -> bool {
    a.start <= b.end && b.start <= a.end
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

fn canonicalize_blocklist(contents: &str) -> String {
    let mut lines = Vec::new();
    let mut entries = Vec::new();
    let mut in_header = true;

    for line in contents.lines() {
        let trimmed = line.trim();

        if in_header {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                lines.push(trimmed.to_string());
                continue;
            }
            in_header = false;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(cidr) = parse_ip_cidr_non_strict(trimmed) {
            entries.push(cidr);
        }
    }

    let canonical_entries = canonical_entry_lines(&entries);
    if !canonical_entries.is_empty() {
        if !lines.is_empty() && !lines.last().is_some_and(|line| line.is_empty()) {
            lines.push(String::new());
        }
        lines.extend(canonical_entries);
    } else if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }

    let mut normalized = lines.join("\n");
    if !normalized.is_empty() {
        normalized.push('\n');
    }
    normalized
}

fn canonical_entry_lines(entries: &[CanonicalCidr]) -> Vec<String> {
    let family_split = split_by_family(entries);
    let collapsed_v4 = collapse_ipv4(&family_split.ipv4);
    let collapsed_v6 = collapse_ipv6(&family_split.ipv6);

    let mut canonical = Vec::new();
    canonical.extend(collapsed_v4.into_iter().map(|cidr| cidr.to_string()));
    canonical.extend(collapsed_v6.into_iter().map(|cidr| cidr.to_string()));

    canonical
}

#[derive(Debug)]
struct BlocklistFile {
    lines: Vec<BlocklistLine>,
    has_content: bool,
    trailing_newline: bool,
}

impl BlocklistFile {
    fn load(path: &Path) -> Result<Self, KidoboError> {
        if !path.exists() {
            return Ok(BlocklistFile {
                lines: Vec::new(),
                has_content: false,
                trailing_newline: false,
            });
        }

        let contents = read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
            KidoboError::BlocklistRead {
                path: path.to_path_buf(),
                reason: err.to_string(),
            }
        })?;

        let lines = contents.lines().map(BlocklistLine::new).collect::<Vec<_>>();

        Ok(BlocklistFile {
            lines,
            has_content: !contents.is_empty(),
            trailing_newline: contents.ends_with('\n'),
        })
    }

    fn contains(&self, canonical: &str) -> bool {
        self.lines
            .iter()
            .filter_map(|line| line.canonical.as_ref().map(|entry| entry.to_string()))
            .any(|entry| entry == canonical)
    }
}

#[derive(Debug)]
struct BlocklistLine {
    original: String,
    canonical: Option<CanonicalCidr>,
}

impl BlocklistLine {
    fn new(line: &str) -> Self {
        let trimmed = line.trim();
        let canonical = if trimmed.is_empty() {
            None
        } else {
            parse_ip_cidr_non_strict(trimmed)
        };

        BlocklistLine {
            original: line.to_string(),
            canonical,
        }
    }
}

#[derive(Debug, Clone)]
struct PartialMatch {
    index: usize,
    entry: String,
}

#[derive(Debug)]
struct UnbanPlan {
    target: String,
    blocklist: BlocklistFile,
    exact_indexes: Vec<usize>,
    partial_matches: Vec<PartialMatch>,
    remove_partial: bool,
}

impl UnbanPlan {
    fn total_removal(&self) -> usize {
        self.exact_indexes.len()
            + if self.remove_partial {
                self.partial_matches.len()
            } else {
                0
            }
    }
}

#[derive(Debug)]
struct UnbanResult {
    removed_exact: usize,
    removed_partial: usize,
}

impl UnbanResult {
    fn total(&self) -> usize {
        self.removed_exact + self.removed_partial
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
        BLOCKLIST_READ_LIMIT, BanOutcome, BlocklistFile, KidoboError, append_blocklist_entry,
        apply_unban_plan, ban_target_in_file, build_unban_plan, ensure_blocklist_parent,
        normalize_local_blocklist, parse_blocklist_target, write_blocklist_lines,
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
        assert!(blocklist.contains("2001:db8::/64"));
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
    fn append_blocklist_entry_handles_newline_states() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");

        append_blocklist_entry(&path, "203.0.113.0/24", false, false).expect("append");
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "203.0.113.0/24\n"
        );

        fs::write(&path, "203.0.113.0/24").expect("write no newline");
        append_blocklist_entry(&path, "198.51.100.0/24", true, false).expect("append2");
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "203.0.113.0/24\n198.51.100.0/24\n"
        );
    }

    #[test]
    fn write_blocklist_lines_creates_newline_and_can_clear() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");

        write_blocklist_lines(&path, &[String::from("a"), String::from("b")]).expect("write");
        assert_eq!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .as_str(),
            "a\nb\n"
        );

        write_blocklist_lines(&path, &[] as &[String]).expect("write empty");
        assert!(
            read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT)
                .expect("read")
                .is_empty()
        );
    }

    #[test]
    fn normalize_local_blocklist_canonicalizes_entries_and_preserves_header_comments() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        fs::write(
            &path,
            "# top comment \n203.0.113.7\n203.0.113.0/24\n2001:db8::/64\n2001:db8::/64\n",
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
}
