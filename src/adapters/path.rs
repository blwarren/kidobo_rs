use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub const ENV_KIDOBO_ROOT: &str = "KIDOBO_ROOT";
pub const ENV_KIDOBO_ALLOW_REPO_CONFIG_FALLBACK: &str = "KIDOBO_ALLOW_REPO_CONFIG_FALLBACK";
pub const ENV_KIDOBO_TEST_SANDBOX: &str = "KIDOBO_TEST_SANDBOX";
pub const ENV_KIDOBO_DISABLE_TEST_SANDBOX: &str = "KIDOBO_DISABLE_TEST_SANDBOX";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathResolutionInput {
    pub explicit_config_path: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub temp_dir: PathBuf,
    pub env: BTreeMap<String, String>,
}

impl PathResolutionInput {
    pub fn from_process(explicit_config_path: Option<PathBuf>) -> Self {
        Self {
            explicit_config_path,
            cwd: env::current_dir().ok(),
            temp_dir: env::temp_dir(),
            env: env::vars().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPaths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub blocklist_file: PathBuf,
    pub cache_dir: PathBuf,
    pub remote_cache_dir: PathBuf,
    pub lock_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BasePaths {
    config_dir: PathBuf,
    config_file: PathBuf,
    data_dir: PathBuf,
    blocklist_file: PathBuf,
    cache_dir: PathBuf,
    remote_cache_dir: PathBuf,
    lock_file: PathBuf,
}

impl BasePaths {
    fn from_root(root: &Path) -> Self {
        let config_dir = root.join("config");
        let data_dir = root.join("data");
        let cache_dir = root.join("cache");

        Self {
            config_file: config_dir.join("config.toml"),
            config_dir,
            blocklist_file: data_dir.join("blocklist.txt"),
            data_dir,
            remote_cache_dir: cache_dir.join("remote"),
            lock_file: cache_dir.join("sync.lock"),
            cache_dir,
        }
    }

    fn system() -> Self {
        Self {
            config_dir: PathBuf::from("/etc/kidobo"),
            config_file: PathBuf::from("/etc/kidobo/config.toml"),
            data_dir: PathBuf::from("/var/lib/kidobo"),
            blocklist_file: PathBuf::from("/var/lib/kidobo/blocklist.txt"),
            cache_dir: PathBuf::from("/var/cache/kidobo"),
            remote_cache_dir: PathBuf::from("/var/cache/kidobo/remote"),
            lock_file: PathBuf::from("/var/cache/kidobo/sync.lock"),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PathResolutionError {
    #[error("could not determine current directory: {reason}")]
    CurrentDirectoryUnavailable { reason: String },

    #[error("explicit config path does not exist: {path}")]
    ExplicitConfigMissing { path: PathBuf },

    #[error("config file not found: {attempted}")]
    MissingConfig { attempted: PathBuf },

    #[error("repo config fallback enabled but repository root was not found from: {start}")]
    RepoRootNotFound { start: PathBuf },

    #[error("repo config fallback enabled but config file is missing: {path}")]
    RepoFallbackConfigMissing { path: PathBuf },
}

pub fn resolve_paths(input: &PathResolutionInput) -> Result<ResolvedPaths, PathResolutionError> {
    resolve_paths_with_policy(input, false)
}

pub fn resolve_paths_for_init(
    input: &PathResolutionInput,
) -> Result<ResolvedPaths, PathResolutionError> {
    resolve_paths_with_policy(input, true)
}

fn resolve_paths_with_policy(
    input: &PathResolutionInput,
    allow_missing_config: bool,
) -> Result<ResolvedPaths, PathResolutionError> {
    let base = derive_base_paths(input);
    let config_file = select_config_path(input, &base, allow_missing_config)?;

    let config_dir = config_file
        .parent()
        .map_or_else(|| base.config_dir.clone(), Path::to_path_buf);

    Ok(ResolvedPaths {
        config_dir,
        config_file,
        data_dir: base.data_dir,
        blocklist_file: base.blocklist_file,
        cache_dir: base.cache_dir,
        remote_cache_dir: base.remote_cache_dir,
        lock_file: base.lock_file,
    })
}

fn derive_base_paths(input: &PathResolutionInput) -> BasePaths {
    if let Some(root) = env_value(&input.env, ENV_KIDOBO_ROOT) {
        return BasePaths::from_root(Path::new(root));
    }

    let sandbox_enabled = env_truthy(&input.env, ENV_KIDOBO_TEST_SANDBOX)
        && !env_present(&input.env, ENV_KIDOBO_DISABLE_TEST_SANDBOX);

    if sandbox_enabled {
        let sandbox_root = input.temp_dir.join("kidobo-tests");
        return BasePaths::from_root(&sandbox_root);
    }

    BasePaths::system()
}

fn select_config_path(
    input: &PathResolutionInput,
    base: &BasePaths,
    allow_missing_config: bool,
) -> Result<PathBuf, PathResolutionError> {
    if let Some(explicit) = input.explicit_config_path.clone() {
        if explicit.exists() || allow_missing_config {
            return Ok(explicit);
        }

        return Err(PathResolutionError::ExplicitConfigMissing { path: explicit });
    }

    if base.config_file.exists() {
        return Ok(base.config_file.clone());
    }

    if env_truthy(&input.env, ENV_KIDOBO_ALLOW_REPO_CONFIG_FALLBACK) {
        let cwd =
            input
                .cwd
                .as_ref()
                .ok_or_else(|| PathResolutionError::CurrentDirectoryUnavailable {
                    reason: "repo config fallback requires a valid current directory".to_string(),
                })?;
        let repo_root = find_repo_root(cwd)
            .ok_or_else(|| PathResolutionError::RepoRootNotFound { start: cwd.clone() })?;

        let fallback = repo_root.join("config.toml");
        if fallback.exists() || allow_missing_config {
            return Ok(fallback);
        }

        return Err(PathResolutionError::RepoFallbackConfigMissing { path: fallback });
    }

    if allow_missing_config {
        Ok(base.config_file.clone())
    } else {
        Err(PathResolutionError::MissingConfig {
            attempted: base.config_file.clone(),
        })
    }
}

fn find_repo_root(start: &Path) -> Option<PathBuf> {
    for candidate in start.ancestors() {
        if candidate.join(".git").exists() {
            return Some(candidate.to_path_buf());
        }
    }

    None
}

fn env_value<'a>(vars: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    vars.get(key).map(String::as_str)
}

fn env_present(vars: &BTreeMap<String, String>, key: &str) -> bool {
    vars.contains_key(key)
}

fn env_truthy(vars: &BTreeMap<String, String>, key: &str) -> bool {
    env_value(vars, key).is_some_and(is_truthy_value)
}

pub fn is_truthy_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::TempDir;

    use super::{
        ENV_KIDOBO_ALLOW_REPO_CONFIG_FALLBACK, ENV_KIDOBO_DISABLE_TEST_SANDBOX, ENV_KIDOBO_ROOT,
        ENV_KIDOBO_TEST_SANDBOX, PathResolutionError, PathResolutionInput, is_truthy_value,
        resolve_paths, resolve_paths_for_init,
    };

    fn test_input(temp: &TempDir) -> PathResolutionInput {
        PathResolutionInput {
            explicit_config_path: None,
            cwd: Some(temp.path().to_path_buf()),
            temp_dir: temp.path().join("tmp"),
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn truthy_values_are_case_insensitive() {
        assert!(is_truthy_value("1"));
        assert!(is_truthy_value("TRUE"));
        assert!(is_truthy_value("Yes"));
        assert!(is_truthy_value("On"));
    }

    #[test]
    fn non_truthy_values_are_false() {
        assert!(!is_truthy_value(""));
        assert!(!is_truthy_value("0"));
        assert!(!is_truthy_value("false"));
        assert!(!is_truthy_value("unexpected"));
    }

    #[test]
    fn kido_root_override_maps_all_paths() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("root");
        let config = root.join("config/config.toml");
        fs::create_dir_all(config.parent().expect("parent")).expect("mkdir");
        fs::write(&config, "[ipset]\nset_name='kidobo'\n").expect("write config");

        let mut input = test_input(&temp);
        input
            .env
            .insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());

        let resolved = resolve_paths(&input).expect("resolve");

        assert_eq!(resolved.config_file, config);
        assert_eq!(resolved.data_dir, root.join("data"));
        assert_eq!(resolved.blocklist_file, root.join("data/blocklist.txt"));
        assert_eq!(resolved.cache_dir, root.join("cache"));
        assert_eq!(resolved.remote_cache_dir, root.join("cache/remote"));
        assert_eq!(resolved.lock_file, root.join("cache/sync.lock"));
    }

    #[test]
    fn test_sandbox_paths_are_used_when_enabled() {
        let temp = TempDir::new().expect("tempdir");
        let sandbox_root = temp.path().join("tmp/kidobo-tests");
        let config = sandbox_root.join("config/config.toml");
        fs::create_dir_all(config.parent().expect("parent")).expect("mkdir");
        fs::write(&config, "[ipset]\nset_name='kidobo'\n").expect("write config");

        let mut input = test_input(&temp);
        input
            .env
            .insert(ENV_KIDOBO_TEST_SANDBOX.to_string(), "true".to_string());

        let resolved = resolve_paths(&input).expect("resolve");

        assert_eq!(resolved.config_file, config);
        assert_eq!(resolved.data_dir, sandbox_root.join("data"));
    }

    #[test]
    fn test_sandbox_is_disabled_when_disable_var_is_set() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("override-root");
        fs::create_dir_all(&root).expect("mkdir root");

        let mut input = test_input(&temp);
        input
            .env
            .insert(ENV_KIDOBO_TEST_SANDBOX.to_string(), "1".to_string());
        input
            .env
            .insert(ENV_KIDOBO_DISABLE_TEST_SANDBOX.to_string(), "1".to_string());
        input
            .env
            .insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());

        let err = resolve_paths(&input).expect_err("should fail without config");
        assert_eq!(
            err,
            PathResolutionError::MissingConfig {
                attempted: root.join("config/config.toml"),
            }
        );
    }

    #[test]
    fn explicit_config_path_wins() {
        let temp = TempDir::new().expect("tempdir");
        let explicit = temp.path().join("custom.toml");
        fs::write(&explicit, "[ipset]\nset_name='kidobo'\n").expect("write config");

        let mut input = test_input(&temp);
        input.explicit_config_path = Some(explicit.clone());

        let resolved = resolve_paths(&input).expect("resolve");
        assert_eq!(resolved.config_file, explicit);
    }

    #[test]
    fn explicit_config_must_exist() {
        let temp = TempDir::new().expect("tempdir");
        let explicit = temp.path().join("missing.toml");

        let mut input = test_input(&temp);
        input.explicit_config_path = Some(explicit.clone());

        let err = resolve_paths(&input).expect_err("must fail");
        assert_eq!(
            err,
            PathResolutionError::ExplicitConfigMissing { path: explicit }
        );
    }

    #[test]
    fn repo_fallback_uses_nearest_git_root() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("override-root");
        let repo = temp.path().join("repo");
        let nested = repo.join("a/b/c");

        fs::create_dir_all(&nested).expect("mkdir nested");
        fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
        fs::write(repo.join("config.toml"), "[ipset]\nset_name='kidobo'\n")
            .expect("write fallback config");

        let mut input = test_input(&temp);
        input.cwd = Some(nested);
        input
            .env
            .insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());
        input.env.insert(
            ENV_KIDOBO_ALLOW_REPO_CONFIG_FALLBACK.to_string(),
            "yes".to_string(),
        );

        let resolved = resolve_paths(&input).expect("resolve");
        assert_eq!(resolved.config_file, repo.join("config.toml"));
    }

    #[test]
    fn repo_fallback_requires_repo_root() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("override-root");
        fs::create_dir_all(&root).expect("mkdir root");

        let mut input = test_input(&temp);
        input.cwd = Some(temp.path().join("outside-repo"));
        let cwd = input.cwd.as_ref().expect("cwd");
        fs::create_dir_all(cwd).expect("mkdir cwd");
        input
            .env
            .insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());
        input.env.insert(
            ENV_KIDOBO_ALLOW_REPO_CONFIG_FALLBACK.to_string(),
            "on".to_string(),
        );

        let err = resolve_paths(&input).expect_err("must fail");
        assert_eq!(
            err,
            PathResolutionError::RepoRootNotFound {
                start: input.cwd.clone().expect("cwd"),
            }
        );
    }

    #[test]
    fn repo_fallback_requires_repo_config_file() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("override-root");
        let repo = temp.path().join("repo");
        let nested = repo.join("nested");

        fs::create_dir_all(&nested).expect("mkdir nested");
        fs::create_dir_all(repo.join(".git")).expect("mkdir .git");

        let mut input = test_input(&temp);
        input.cwd = Some(nested);
        input
            .env
            .insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());
        input.env.insert(
            ENV_KIDOBO_ALLOW_REPO_CONFIG_FALLBACK.to_string(),
            "true".to_string(),
        );

        let err = resolve_paths(&input).expect_err("must fail");
        assert_eq!(
            err,
            PathResolutionError::RepoFallbackConfigMissing {
                path: repo.join("config.toml"),
            }
        );
    }

    #[test]
    fn missing_config_without_repo_fallback_fails() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("override-root");
        fs::create_dir_all(&root).expect("mkdir root");

        let mut input = test_input(&temp);
        input
            .env
            .insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());

        let err = resolve_paths(&input).expect_err("must fail");
        assert_eq!(
            err,
            PathResolutionError::MissingConfig {
                attempted: root.join("config/config.toml"),
            }
        );
    }

    #[test]
    fn init_resolution_allows_missing_default_config_path() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("root");
        fs::create_dir_all(&root).expect("mkdir root");

        let mut input = test_input(&temp);
        input
            .env
            .insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());

        let resolved = resolve_paths_for_init(&input).expect("resolve");
        assert_eq!(resolved.config_file, root.join("config/config.toml"));
    }

    #[test]
    fn init_resolution_allows_missing_repo_fallback_config() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("root");
        let repo = temp.path().join("repo");
        fs::create_dir_all(&root).expect("mkdir root");
        fs::create_dir_all(repo.join(".git")).expect("mkdir .git");

        let mut input = test_input(&temp);
        input.cwd = Some(repo.join("nested"));
        let cwd = input.cwd.as_ref().expect("cwd");
        fs::create_dir_all(cwd).expect("mkdir nested");
        input
            .env
            .insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());
        input.env.insert(
            ENV_KIDOBO_ALLOW_REPO_CONFIG_FALLBACK.to_string(),
            "yes".to_string(),
        );

        let resolved = resolve_paths_for_init(&input).expect("resolve");
        assert_eq!(resolved.config_file, repo.join("config.toml"));
    }

    #[test]
    fn repo_fallback_requires_valid_current_directory() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("override-root");
        fs::create_dir_all(&root).expect("mkdir root");

        let mut input = test_input(&temp);
        input.cwd = None;
        input
            .env
            .insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());
        input.env.insert(
            ENV_KIDOBO_ALLOW_REPO_CONFIG_FALLBACK.to_string(),
            "true".to_string(),
        );

        let err = resolve_paths(&input).expect_err("must fail");
        assert_eq!(
            err,
            PathResolutionError::CurrentDirectoryUnavailable {
                reason: "repo config fallback requires a valid current directory".to_string(),
            }
        );
    }
}
