use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;

use crate::adapters::blocklist_file::{
    BLOCKLIST_READ_LIMIT, BlocklistDocument, BlocklistNormalizeResult, ensure_blocklist_parent,
    normalize_local_blocklist, normalize_local_blocklist_with_fast_state, write_blocklist_lines,
};
use crate::adapters::limited_io::read_to_string_with_limit;
use crate::core::blocklist::canonicalize_blocklist;
use crate::core::network::parse_ip_cidr_non_strict;

use super::asn::remove_exact_blocklist_duplicates;
use super::plan::{apply_unban_plan, build_unban_plan, parse_blocklist_target};
use super::targets::{
    BLOCKLIST_TARGET_FILE_READ_LIMIT, BanOutcome, ban_target_in_file, ban_targets_in_file,
    read_blocklist_target_lines,
};
use crate::error::KidoboError;

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
fn ban_file_appends_new_entries_and_reports_existing() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("blocklist.txt");
    fs::write(&path, "203.0.113.0/24\n").expect("write blocklist");

    let targets = vec![
        parse_ip_cidr_non_strict("203.0.113.0/24").expect("existing"),
        parse_ip_cidr_non_strict("198.51.100.0/24").expect("new"),
    ];
    let outcomes = ban_targets_in_file(&path, &targets).expect("ban file");

    assert_eq!(
        outcomes,
        vec![
            BanOutcome::AlreadyPresent("203.0.113.0/24".into()),
            BanOutcome::Added("198.51.100.0/24".into()),
        ]
    );
}

#[test]
fn blocklist_document_load_preserves_original_lines() {
    let temp = TempDir::new().expect("tempdir");
    let path = write_temp_file(&temp, "# header\n203.0.113.0/24\n# comment\n");

    let blocklist = BlocklistDocument::load(&path).expect("load");
    assert_eq!(blocklist.lines.len(), 3);
    assert_eq!(blocklist.lines[0].original, "# header");
    assert_eq!(blocklist.lines[1].original, "203.0.113.0/24");
    assert_eq!(blocklist.lines[2].original, "# comment");
}

#[test]
fn blocklist_load_rejects_invalid_lines() {
    let temp = TempDir::new().expect("tempdir");
    let path = write_temp_file(&temp, "203.0.113.0/24 trailing\n");

    let err = BlocklistDocument::load(&path).expect_err("invalid line must fail");
    assert!(matches!(
        err,
        KidoboError::BlocklistParseLine { line: 1, .. }
    ));
}

#[test]
fn canonicalization_preserves_header_behavior() {
    let normalized = canonicalize_blocklist(
        "# top comment \n203.0.113.7\n# dropped later comment\n203.0.113.0/24\n2001:db8::/64\n2001:db8::/64\n",
    )
    .expect("canonicalize");

    assert_eq!(
        normalized,
        "# top comment\n\n203.0.113.0/24\n2001:db8::/64\n"
    );
}

#[test]
fn remove_exact_blocklist_duplicates_only_removes_exact_entries() {
    let temp = TempDir::new().expect("tempdir");
    let path = write_temp_file(&temp, "203.0.113.0/24\n203.0.113.7\n198.51.100.0/24\n");

    let removed = remove_exact_blocklist_duplicates(
        &path,
        &[parse_ip_cidr_non_strict("203.0.113.7").expect("target")],
    )
    .expect("remove duplicates");
    assert_eq!(removed, 1);

    let contents = read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT).expect("read");
    assert_eq!(contents, "203.0.113.0/24\n198.51.100.0/24\n");
}

#[test]
fn build_unban_plan_detects_exact_and_partial_matches() {
    let temp = TempDir::new().expect("tempdir");
    let path = write_temp_file(&temp, "203.0.113.0/24\n203.0.113.7\n");

    let plan = build_unban_plan(&path, "203.0.113.7").expect("plan");
    assert_eq!(plan.exact_indexes, vec![1]);
    assert_eq!(plan.partial_matches.len(), 1);
    assert_eq!(plan.partial_matches[0].entry, "203.0.113.0/24");
}

#[test]
fn apply_unban_plan_preserves_unrelated_lines() {
    let temp = TempDir::new().expect("tempdir");
    let path = write_temp_file(&temp, "# header\n203.0.113.0/24\n203.0.113.7\n");

    let mut plan = build_unban_plan(&path, "203.0.113.7").expect("plan");
    plan.remove_partial = true;
    let result = apply_unban_plan(&path, &plan).expect("apply");

    assert_eq!(result.total(), 2);
    let contents = read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT).expect("read");
    assert_eq!(contents, "# header\n");
}

#[test]
fn read_blocklist_target_lines_reads_file_contents() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("targets.txt");
    fs::write(&path, "203.0.113.7\n198.51.100.0/24\n").expect("write targets");

    let lines = read_blocklist_target_lines(&path).expect("read");
    assert_eq!(lines, vec!["203.0.113.7", "198.51.100.0/24"]);
}

#[test]
fn read_blocklist_target_lines_enforces_limit() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("targets.txt");
    let oversized = "x".repeat(BLOCKLIST_TARGET_FILE_READ_LIMIT + 1);
    fs::write(&path, oversized).expect("write targets");

    let err = read_blocklist_target_lines(&path).expect_err("must fail");
    assert!(matches!(err, KidoboError::BlocklistTargetFileRead { .. }));
}

#[test]
fn normalize_local_blocklist_skips_missing_file() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("missing.txt");

    normalize_local_blocklist(&path).expect("normalize");
    assert!(!path.exists());
}

#[test]
fn normalize_local_blocklist_with_fast_state_skips_unchanged_file() {
    let temp = TempDir::new().expect("tempdir");
    let path = write_temp_file(&temp, "203.0.113.7\n203.0.113.0/24\n");
    let state_path = temp.path().join("state.txt");

    let first =
        normalize_local_blocklist_with_fast_state(&path, &state_path).expect("first normalize");
    assert_eq!(first, BlocklistNormalizeResult::Checked);

    let second =
        normalize_local_blocklist_with_fast_state(&path, &state_path).expect("second normalize");
    assert_eq!(second, BlocklistNormalizeResult::SkippedUnchanged);
}

#[test]
fn normalize_local_blocklist_with_fast_state_handles_missing_blocklist() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("missing.txt");
    let state_path = temp.path().join("state.txt");

    let result = normalize_local_blocklist_with_fast_state(&path, &state_path).expect("normalize");
    assert_eq!(result, BlocklistNormalizeResult::MissingBlocklist);
}

#[test]
fn ensure_blocklist_parent_creates_parent_directory() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("nested/blocklist.txt");

    ensure_blocklist_parent(&path).expect("mkdir");
    assert!(path.parent().expect("parent").exists());
}

#[test]
fn write_blocklist_lines_writes_newline_terminated_contents() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("blocklist.txt");

    write_blocklist_lines(&path, &["203.0.113.0/24", "198.51.100.0/24"]).expect("write");
    let contents = read_to_string_with_limit(&path, BLOCKLIST_READ_LIMIT).expect("read");
    assert_eq!(contents, "203.0.113.0/24\n198.51.100.0/24\n");
}

#[test]
fn parse_blocklist_target_trims_and_validates() {
    let parsed = parse_blocklist_target(" 203.0.113.7 ").expect("parse");
    assert_eq!(
        parsed,
        parse_ip_cidr_non_strict("203.0.113.7").expect("expected")
    );
}

#[test]
fn parse_blocklist_target_accepts_ipv6() {
    let parsed = parse_blocklist_target("2001:db8::/64").expect("parse");
    assert_eq!(
        parsed,
        parse_ip_cidr_non_strict("2001:db8::/64").expect("expected")
    );
}
