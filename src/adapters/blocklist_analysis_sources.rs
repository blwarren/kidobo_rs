use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Deserialize;
use thiserror::Error;

use crate::adapters::limited_io::read_to_string_with_limit;
use crate::adapters::path::ResolvedPaths;
use crate::core::network::{CanonicalCidr, parse_ip_cidr_token};

const SOURCE_FILE_READ_LIMIT: usize = 16 * 1024 * 1024;
const REMOTE_META_READ_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRemoteSource {
    pub label: String,
    pub cidrs: Vec<CanonicalCidr>,
    pub stale: bool,
    pub age_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisSources {
    pub local_cidrs: Vec<CanonicalCidr>,
    pub remote_sources: Vec<AnalysisRemoteSource>,
}

#[derive(Debug, Error)]
pub enum AnalysisSourceLoadError {
    #[error("failed to read source file {path}: {reason}")]
    SourceRead { path: PathBuf, reason: String },

    #[error("failed to read remote cache directory {path}: {reason}")]
    CacheDirRead { path: PathBuf, reason: String },

    #[error("failed to read remote cache directory entry in {path}: {reason}")]
    CacheDirEntryRead { path: PathBuf, reason: String },
}

pub fn load_analysis_sources(
    paths: &ResolvedPaths,
    stale_after_secs: u64,
) -> Result<AnalysisSources, AnalysisSourceLoadError> {
    let mut local_cidrs = Vec::new();
    if paths.blocklist_file.exists() {
        local_cidrs = read_source_file(&paths.blocklist_file)?;
    }

    let mut remote_sources = Vec::new();
    if paths.remote_cache_dir.exists() {
        let mut remote_files = collect_remote_cache_files(paths)?;
        remote_files.sort();

        for file in remote_files {
            let cidrs = read_source_file(&file)?;
            let label = resolve_remote_source_label(&file);
            let age_secs = cache_age_secs(&file);
            let stale = age_secs.is_some_and(|age| age > stale_after_secs);
            remote_sources.push(AnalysisRemoteSource {
                label,
                cidrs,
                stale,
                age_secs,
            });
        }
    }

    Ok(AnalysisSources {
        local_cidrs,
        remote_sources,
    })
}

fn collect_remote_cache_files(
    paths: &ResolvedPaths,
) -> Result<Vec<PathBuf>, AnalysisSourceLoadError> {
    let mut files = Vec::new();
    let dir_iter = fs::read_dir(&paths.remote_cache_dir).map_err(|err| {
        AnalysisSourceLoadError::CacheDirRead {
            path: paths.remote_cache_dir.clone(),
            reason: err.to_string(),
        }
    })?;

    for entry in dir_iter {
        let entry = entry.map_err(|err| AnalysisSourceLoadError::CacheDirEntryRead {
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

fn read_source_file(path: &Path) -> Result<Vec<CanonicalCidr>, AnalysisSourceLoadError> {
    let contents = read_to_string_with_limit(path, SOURCE_FILE_READ_LIMIT).map_err(|err| {
        AnalysisSourceLoadError::SourceRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    let mut entries = Vec::new();
    for raw_line in contents.lines() {
        if let Some(cidr) = parse_source_line(raw_line) {
            entries.push(cidr);
        }
    }
    Ok(entries)
}

fn parse_source_line(line: &str) -> Option<CanonicalCidr> {
    let token = line.split_whitespace().next()?.trim();
    if token.is_empty() {
        return None;
    }
    parse_ip_cidr_token(token)
}

fn cache_age_secs(path: &Path) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let duration = SystemTime::now().duration_since(modified).ok()?;
    Some(duration.as_secs())
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

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::load_analysis_sources;
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
    fn loads_local_and_remote_sources_with_stale_flag() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");

        fs::write(&paths.blocklist_file, "10.0.0.0/24\n").expect("write blocklist");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "203.0.113.0/24\n")
            .expect("write remote");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            r#"{"url":"https://example.com/a.txt"}"#,
        )
        .expect("write meta");

        let sources = load_analysis_sources(&paths, 86_400).expect("load");
        assert_eq!(sources.local_cidrs.len(), 1);
        assert_eq!(sources.remote_sources.len(), 1);
        assert_eq!(sources.remote_sources[0].label, "https://example.com/a.txt");
        assert!(!sources.remote_sources[0].stale);
        assert!(sources.remote_sources[0].age_secs.is_some());
    }
}
