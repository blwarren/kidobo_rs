use std::ffi::OsStr;
use std::fs;

use thiserror::Error;

use crate::adapters::path::ResolvedPaths;
use crate::core::lookup::LookupSourceEntry;
use crate::core::network::parse_ip_cidr_non_strict;

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
            let file_name = file
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or("unknown.iplist")
                .to_string();
            let source_label = format!("remote:{file_name}");
            entries.extend(read_source_file(&file, &source_label)?);
        }
    }

    entries
        .sort_by(|a, b| (&a.source_label, &a.source_line).cmp(&(&b.source_label, &b.source_line)));
    Ok(entries)
}

fn collect_remote_cache_files(
    paths: &ResolvedPaths,
) -> Result<Vec<std::path::PathBuf>, LookupSourceLoadError> {
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
    path: &std::path::Path,
    source_label: &str,
) -> Result<Vec<LookupSourceEntry>, LookupSourceLoadError> {
    let contents = fs::read_to_string(path).map_err(|err| LookupSourceLoadError::SourceRead {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;

    let mut entries = Vec::new();
    for raw_line in contents.lines() {
        if let Some((cidr, token)) = parse_lookup_source_line(raw_line) {
            entries.push(LookupSourceEntry {
                source_label: source_label.to_string(),
                source_line: token,
                cidr,
            });
        }
    }

    Ok(entries)
}

fn parse_lookup_source_line(line: &str) -> Option<(crate::core::network::CanonicalCidr, String)> {
    let token = line.split_whitespace().next()?.trim();
    if token.is_empty() {
        return None;
    }

    let cidr = parse_ip_cidr_non_strict(token)?;
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
        fs::write(paths.remote_cache_dir.join("ignore.txt"), "10.0.0.1\n").expect("write ignore");

        let entries = load_lookup_sources(&paths).expect("load sources");

        let labels = entries
            .iter()
            .map(|entry| entry.source_label.as_str())
            .collect::<Vec<_>>();
        let lines = entries
            .iter()
            .map(|entry| entry.source_line.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            labels,
            vec![
                "internal:blocklist",
                "internal:blocklist",
                "remote:a.iplist"
            ]
        );
        assert_eq!(lines, vec!["10.0.0.0/24", "198.51.100.7", "2001:db8::/64"]);
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
