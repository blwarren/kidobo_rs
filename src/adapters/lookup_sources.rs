use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;

use crate::adapters::limited_io::read_to_string_with_limit;
use crate::adapters::path::ResolvedPaths;
use crate::adapters::source_files::{
    REMOTE_META_READ_LIMIT, RemoteCacheFilesError, SOURCE_FILE_READ_LIMIT,
    collect_remote_cache_files as collect_remote_cache_iplist_files, parse_cidr_source_line,
    resolve_remote_source_label,
};
use crate::core::lookup::LookupSourceEntry;

#[derive(Debug, Error)]
pub enum LookupSourceLoadError {
    #[error("failed to read source file {path}: {reason}")]
    SourceRead {
        path: std::path::PathBuf,
        reason: String,
    },

    #[error("failed to read remote cache directory {path}: {reason}")]
    CacheDirRead {
        path: std::path::PathBuf,
        reason: String,
    },

    #[error("failed to read remote cache directory entry in {path}: {reason}")]
    CacheDirEntryRead {
        path: std::path::PathBuf,
        reason: String,
    },
}

pub fn load_lookup_sources(
    paths: &ResolvedPaths,
) -> Result<Vec<LookupSourceEntry>, LookupSourceLoadError> {
    let mut entries = Vec::new();

    if paths.blocklist_file.exists() {
        entries.extend(read_source_file(
            &paths.blocklist_file,
            "internal:blocklist",
        )?);
    }

    if paths.remote_cache_dir.exists() {
        let mut remote_files = collect_remote_cache_files(paths)?;
        remote_files.sort();

        for file in remote_files {
            let source_label = resolve_remote_source_label(&file, REMOTE_META_READ_LIMIT);
            entries.extend(read_source_file(&file, &source_label)?);
        }
    }

    entries
        .sort_by(|a, b| (&a.source_label, &a.source_line).cmp(&(&b.source_label, &b.source_line)));
    Ok(entries)
}

fn collect_remote_cache_files(
    paths: &ResolvedPaths,
) -> Result<Vec<PathBuf>, LookupSourceLoadError> {
    collect_remote_cache_iplist_files(&paths.remote_cache_dir).map_err(|err| match err {
        RemoteCacheFilesError::ReadDir(err) => LookupSourceLoadError::CacheDirRead {
            path: paths.remote_cache_dir.clone(),
            reason: err.to_string(),
        },
        RemoteCacheFilesError::ReadDirEntry(err) => LookupSourceLoadError::CacheDirEntryRead {
            path: paths.remote_cache_dir.clone(),
            reason: err.to_string(),
        },
    })
}

fn read_source_file(
    path: &Path,
    source_label: &str,
) -> Result<Vec<LookupSourceEntry>, LookupSourceLoadError> {
    let contents = read_to_string_with_limit(path, SOURCE_FILE_READ_LIMIT).map_err(|err| {
        LookupSourceLoadError::SourceRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    let source_label: Arc<str> = Arc::from(source_label);
    Ok(contents
        .lines()
        .filter_map(parse_lookup_source_line)
        .map(|(cidr, token)| LookupSourceEntry {
            source_label: Arc::clone(&source_label),
            source_line: token.to_string(),
            cidr,
        })
        .collect())
}

fn parse_lookup_source_line(line: &str) -> Option<(crate::core::network::CanonicalCidr, &str)> {
    parse_cidr_source_line(line)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::load_lookup_sources;
    use crate::adapters::path::ResolvedPaths;

    fn test_paths(root: &std::path::Path) -> ResolvedPaths {
        ResolvedPaths {
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            blocklist_file: root.join("data/blocklist.txt"),
            cache_dir: root.join("cache"),
            remote_cache_dir: root.join("cache/remote"),
            lock_file: root.join("cache/sync.lock"),
        }
    }

    #[test]
    fn loads_blocklist_and_remote_cached_sources() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");

        fs::write(
            &paths.blocklist_file,
            "10.0.0.0/24\ninvalid\n198.51.100.7 trailing\n",
        )
        .expect("write blocklist");

        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            r#"{"url":"https://example.com/allowlist.txt"}"#,
        )
        .expect("write remote meta");
        fs::write(paths.remote_cache_dir.join("ignore.txt"), "10.0.0.1\n").expect("write ignore");

        let entries = load_lookup_sources(&paths).expect("load sources");

        let labels = entries
            .iter()
            .map(|entry| entry.source_label.as_ref())
            .collect::<Vec<_>>();
        let lines = entries
            .iter()
            .map(|entry| entry.source_line.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            labels,
            vec![
                "https://example.com/allowlist.txt",
                "internal:blocklist",
                "internal:blocklist"
            ]
        );
        assert_eq!(lines, vec!["2001:db8::/64", "10.0.0.0/24", "198.51.100.7"]);
    }

    #[test]
    fn remote_source_label_falls_back_to_cache_file_when_metadata_missing() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");

        let entries = load_lookup_sources(&paths).expect("load sources");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_label.as_ref(), "remote:a.iplist");
    }

    #[test]
    fn remote_source_label_falls_back_to_cache_file_when_metadata_invalid() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");
        fs::write(paths.remote_cache_dir.join("a.meta.json"), "{").expect("write invalid meta");

        let entries = load_lookup_sources(&paths).expect("load sources");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_label.as_ref(), "remote:a.iplist");
    }

    #[test]
    fn remote_entries_are_sorted_by_resolved_label_not_cache_filename() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            r#"{"url":"https://example.com/z.txt"}"#,
        )
        .expect("write remote meta a");
        fs::write(paths.remote_cache_dir.join("b.iplist"), "10.0.0.0/24\n")
            .expect("write remote b");
        fs::write(
            paths.remote_cache_dir.join("b.meta.json"),
            r#"{"url":"https://example.com/a.txt"}"#,
        )
        .expect("write remote meta b");

        let entries = load_lookup_sources(&paths).expect("load sources");
        let labels = entries
            .iter()
            .map(|entry| entry.source_label.as_ref())
            .collect::<Vec<_>>();

        assert_eq!(
            labels,
            vec!["https://example.com/a.txt", "https://example.com/z.txt"]
        );
    }

    #[test]
    fn multiple_remote_files_with_same_label_are_all_loaded() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");
        fs::write(paths.remote_cache_dir.join("b.iplist"), "10.0.0.0/24\n")
            .expect("write remote b");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            r#"{"url":"https://example.com/shared.txt"}"#,
        )
        .expect("write remote meta a");
        fs::write(
            paths.remote_cache_dir.join("b.meta.json"),
            r#"{"url":"https://example.com/shared.txt"}"#,
        )
        .expect("write remote meta b");

        let entries = load_lookup_sources(&paths).expect("load sources");
        let rendered = entries
            .iter()
            .map(|entry| {
                (
                    entry.source_label.as_ref().to_string(),
                    entry.source_line.clone(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                (
                    "https://example.com/shared.txt".to_string(),
                    "10.0.0.0/24".to_string(),
                ),
                (
                    "https://example.com/shared.txt".to_string(),
                    "2001:db8::/64".to_string(),
                ),
            ]
        );
    }

    #[test]
    fn missing_source_files_return_empty_entries() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        let entries = load_lookup_sources(&paths).expect("load sources");
        assert!(entries.is_empty());
    }

    #[test]
    fn source_read_errors_are_reported() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.blocklist_file).expect("make dir instead of file");

        let err = load_lookup_sources(&paths).expect_err("must fail");
        assert!(err.to_string().contains("failed to read source file"));
    }

    #[test]
    fn oversized_remote_iplist_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(
            paths.remote_cache_dir.join("a.iplist"),
            "1".repeat(super::SOURCE_FILE_READ_LIMIT + 1),
        )
        .expect("write oversized iplist");

        let err = load_lookup_sources(&paths).expect_err("must fail");
        match err {
            super::LookupSourceLoadError::SourceRead { reason, .. } => {
                assert!(reason.contains("file exceeds 16777216 byte limit"));
            }
            _ => panic!("expected source read error"),
        }
    }

    #[test]
    fn cache_dir_entry_errors_are_reported() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.remote_cache_dir.parent().expect("parent")).expect("mkdir cache");
        fs::write(&paths.remote_cache_dir, "not a directory").expect("write file");

        let err = load_lookup_sources(&paths).expect_err("must fail");
        assert!(matches!(
            err,
            super::LookupSourceLoadError::CacheDirRead { .. }
                | super::LookupSourceLoadError::CacheDirEntryRead { .. }
        ));
    }

    #[test]
    fn parse_lookup_source_line_tolerates_comments_and_blank_lines() {
        assert!(super::parse_lookup_source_line("# comment").is_none());
        assert!(super::parse_lookup_source_line("   ").is_none());

        let parsed = super::parse_lookup_source_line("203.0.113.1 # trailing").expect("parse");
        assert_eq!(parsed.1, "203.0.113.1");
    }

    #[test]
    fn io_error_display_is_stable() {
        let io_err = std::io::Error::other("boom");
        assert_eq!(io_err.to_string(), "boom");
    }
}
