use std::fs;
use std::path::Path;

use crate::adapters::path::{PathResolutionInput, ResolvedPaths, resolve_paths_for_init};
use crate::error::KidoboError;

const DEFAULT_CONFIG_TEMPLATE: &str = r#"[ipset]
set_name = "kidobo"

[safe]
ips = []
include_github_meta = true
# github_meta_categories = ["api", "git", "hooks", "packages"]

[remote]
urls = []
"#;

const DEFAULT_BLOCKLIST_TEMPLATE: &str =
    "# Add one IP or CIDR entry per line.\n# Example: 203.0.113.7\n";

pub fn run_init_command() -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None)?;
    let paths = resolve_paths_for_init(&path_input)?;
    run_init_with_paths(&paths)
}

pub(crate) fn run_init_with_paths(paths: &ResolvedPaths) -> Result<(), KidoboError> {
    ensure_dir(&paths.config_dir)?;
    ensure_dir(&paths.data_dir)?;
    ensure_dir(&paths.remote_cache_dir)?;

    ensure_file_if_missing(&paths.config_file, DEFAULT_CONFIG_TEMPLATE)?;
    ensure_file_if_missing(&paths.blocklist_file, DEFAULT_BLOCKLIST_TEMPLATE)?;

    Ok(())
}

fn ensure_dir(path: &Path) -> Result<(), KidoboError> {
    fs::create_dir_all(path).map_err(|err| KidoboError::InitIo {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

fn ensure_file_if_missing(path: &Path, contents: &str) -> Result<(), KidoboError> {
    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }

    fs::write(path, contents).map_err(|err| KidoboError::InitIo {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{DEFAULT_BLOCKLIST_TEMPLATE, DEFAULT_CONFIG_TEMPLATE, run_init_with_paths};
    use crate::adapters::path::ResolvedPaths;

    fn test_paths(root: &Path) -> ResolvedPaths {
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
    fn init_creates_directories_and_default_files() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        run_init_with_paths(&paths).expect("init");

        assert!(paths.config_dir.exists());
        assert!(paths.data_dir.exists());
        assert!(paths.remote_cache_dir.exists());

        let config = fs::read_to_string(&paths.config_file).expect("config");
        assert_eq!(config, DEFAULT_CONFIG_TEMPLATE);

        let blocklist = fs::read_to_string(&paths.blocklist_file).expect("blocklist");
        assert_eq!(blocklist, DEFAULT_BLOCKLIST_TEMPLATE);
    }

    #[test]
    fn init_does_not_overwrite_existing_files() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.config_dir).expect("mkdir config");
        fs::create_dir_all(&paths.data_dir).expect("mkdir data");
        fs::write(&paths.config_file, "custom-config").expect("write config");
        fs::write(&paths.blocklist_file, "custom-blocklist").expect("write blocklist");

        run_init_with_paths(&paths).expect("init");

        let config = fs::read_to_string(&paths.config_file).expect("config");
        assert_eq!(config, "custom-config");

        let blocklist = fs::read_to_string(&paths.blocklist_file).expect("blocklist");
        assert_eq!(blocklist, "custom-blocklist");
    }

    #[test]
    fn init_handles_repeated_runs_idempotently() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        run_init_with_paths(&paths).expect("first");
        run_init_with_paths(&paths).expect("second");

        assert_eq!(
            fs::read_to_string(&paths.config_file).expect("config"),
            DEFAULT_CONFIG_TEMPLATE
        );
        assert_eq!(
            fs::read_to_string(&paths.blocklist_file).expect("blocklist"),
            DEFAULT_BLOCKLIST_TEMPLATE
        );
    }

    #[test]
    fn init_returns_error_when_parent_is_not_directory() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();

        let paths = ResolvedPaths {
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            blocklist_file: root.join("data/blocklist.txt"),
            cache_dir: root.join("cache"),
            remote_cache_dir: root.join("cache/remote"),
            lock_file: root.join("cache/sync.lock"),
        };

        fs::write(PathBuf::from(&paths.cache_dir), "not-a-directory").expect("write blocker");

        let err = run_init_with_paths(&paths).expect_err("must fail");
        let message = err.to_string();
        assert!(
            message.contains("cache/remote") || message.contains("cache"),
            "unexpected error: {message}"
        );
    }
}
