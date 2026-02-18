use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use thiserror::Error;

use crate::adapters::limited_io::read_to_string_with_limit;
use crate::adapters::path::ResolvedPaths;
use crate::core::lookup::LookupSourceEntry;
use crate::core::network::parse_ip_cidr_token;

const SOURCE_FILE_READ_LIMIT: usize = 16 * 1024 * 1024;
const REMOTE_META_READ_LIMIT: usize = 256 * 1024;

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
            let source_label = resolve_remote_source_label(&file);
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
    let mut files = Vec::new();
    let dir_iter = fs::read_dir(&paths.remote_cache_dir).map_err(|err| {
        LookupSourceLoadError::CacheDirRead {
            path: paths.remote_cache_dir.clone(),
            reason: err.to_string(),
        }
    })?;

    for entry in dir_iter {
        let entry = entry.map_err(|err| LookupSourceLoadError::CacheDirEntryRead {
            path: paths.remote_cache_dir.clone(),
            reason: err.to_string(),
        })?;

        let path = entry.path();
        if path.is_file() && path.extension() == Some(OsStr::new("iplist")) {
            files.push(path);
        }
    }

    Ok(files)
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
    let mut entries = Vec::new();
    for raw_line in contents.lines() {
        if let Some((cidr, token)) = parse_lookup_source_line(raw_line) {
            entries.push(LookupSourceEntry {
                source_label: Arc::clone(&source_label),
                source_line: token,
                cidr,
            });
        }
    }

    Ok(entries)
}

#[derive(Debug, Deserialize)]
struct RemoteSourceMetadata {
    url: String,
}

fn resolve_remote_source_label(iplist_path: &Path) -> String {
    let Some(meta_path) = remote_meta_path_for_iplist(iplist_path) else {
        return fallback_remote_source_label(iplist_path);
    };

    let Ok(contents) = read_to_string_with_limit(&meta_path, REMOTE_META_READ_LIMIT) else {
        return fallback_remote_source_label(iplist_path);
    };

    let Ok(metadata) = serde_json::from_str::<RemoteSourceMetadata>(&contents) else {
        return fallback_remote_source_label(iplist_path);
    };

    let normalized_url = metadata.url.trim();
    if normalized_url.is_empty() {
        return fallback_remote_source_label(iplist_path);
    }

    normalized_url.to_string()
}

fn remote_meta_path_for_iplist(iplist_path: &Path) -> Option<PathBuf> {
    let stem = iplist_path.file_stem()?.to_str()?;
    Some(iplist_path.with_file_name(format!("{stem}.meta.json")))
}

fn fallback_remote_source_label(iplist_path: &Path) -> String {
    let file_name = iplist_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("unknown.iplist");
    format!("remote:{file_name}")
}

fn parse_lookup_source_line(line: &str) -> Option<(crate::core::network::CanonicalCidr, String)> {
    let token = line.split_whitespace().next()?.trim();
    if token.is_empty() {
        return None;
    }

    let cidr = parse_ip_cidr_token(token)?;
    Some((cidr, token.to_string()))
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
