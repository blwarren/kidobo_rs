use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::adapters::path::{
    ENV_KIDOBO_ROOT, PathResolutionInput, ResolvedPaths, resolve_paths_for_init,
};
use crate::error::KidoboError;

const DEFAULT_CONFIG_TEMPLATE: &str = r#"[ipset]
set_name = "kidobo"

[safe]
ips = []
include_github_meta = true
github_meta_url = "https://api.github.com/meta"
# github_meta_categories = ["api", "git", "hooks", "packages"]

[remote]
urls = []
"#;

const DEFAULT_BLOCKLIST_TEMPLATE: &str =
    "# Add one IP or CIDR entry per line.\n# Example: 203.0.113.7\n";

const DEFAULT_KIDOBO_BINARY_PATH: &str = "/usr/local/bin/kidobo";
const DEFAULT_SYSTEMD_DIR: &str = "/etc/systemd/system";
const KIDOBO_SYNC_SERVICE_FILE: &str = "kidobo-sync.service";
const KIDOBO_SYNC_TIMER_FILE: &str = "kidobo-sync.timer";

const DEFAULT_SYSTEMD_TIMER_TEMPLATE: &str = r#"[Unit]
Description=Run kidobo sync periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true
Unit=kidobo-sync.service

[Install]
WantedBy=timers.target
"#;

pub fn run_init_command() -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None)?;
    let paths = resolve_paths_for_init(&path_input)?;
    let executable_path =
        env::current_exe().unwrap_or_else(|_| PathBuf::from(DEFAULT_KIDOBO_BINARY_PATH));
    let kido_root_override = path_input.env.get(ENV_KIDOBO_ROOT).map(PathBuf::from);
    run_init_with_context(&paths, &executable_path, kido_root_override.as_deref())
}

#[cfg(test)]
pub(crate) fn run_init_with_paths(paths: &ResolvedPaths) -> Result<(), KidoboError> {
    let executable_path = PathBuf::from(DEFAULT_KIDOBO_BINARY_PATH);
    let kido_root_override = infer_kido_root_override(paths);
    run_init_with_context(paths, &executable_path, kido_root_override.as_deref())
}

fn run_init_with_context(
    paths: &ResolvedPaths,
    executable_path: &Path,
    kido_root_override: Option<&Path>,
) -> Result<(), KidoboError> {
    let systemd_dir = resolve_systemd_dir(kido_root_override);
    let systemd_service = systemd_dir.join(KIDOBO_SYNC_SERVICE_FILE);
    let systemd_timer = systemd_dir.join(KIDOBO_SYNC_TIMER_FILE);

    ensure_dir(&paths.config_dir)?;
    ensure_dir(&paths.data_dir)?;
    ensure_dir(&paths.remote_cache_dir)?;
    ensure_dir(&systemd_dir)?;

    ensure_file_if_missing(&paths.config_file, DEFAULT_CONFIG_TEMPLATE)?;
    ensure_file_if_missing(&paths.blocklist_file, DEFAULT_BLOCKLIST_TEMPLATE)?;
    ensure_file_if_missing(&paths.lock_file, "")?;
    ensure_file_if_missing(
        &systemd_service,
        &build_systemd_service_template(executable_path, kido_root_override),
    )?;
    ensure_file_if_missing(&systemd_timer, DEFAULT_SYSTEMD_TIMER_TEMPLATE)?;

    Ok(())
}

fn resolve_systemd_dir(kido_root_override: Option<&Path>) -> PathBuf {
    kido_root_override.map_or_else(
        || PathBuf::from(DEFAULT_SYSTEMD_DIR),
        |root| root.join("systemd/system"),
    )
}

#[cfg(test)]
fn infer_kido_root_override(paths: &ResolvedPaths) -> Option<PathBuf> {
    let root = paths.config_dir.parent()?.to_path_buf();
    if paths.config_dir != root.join("config") {
        return None;
    }

    if paths.data_dir != root.join("data")
        || paths.blocklist_file != root.join("data/blocklist.txt")
        || paths.cache_dir != root.join("cache")
        || paths.remote_cache_dir != root.join("cache/remote")
        || paths.lock_file != root.join("cache/sync.lock")
    {
        return None;
    }

    Some(root)
}

fn build_systemd_service_template(
    executable_path: &Path,
    kido_root_override: Option<&Path>,
) -> String {
    let mut output = String::from(
        "[Unit]\n\
Description=Kidobo firewall blocklist sync\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=oneshot\n",
    );

    if let Some(root) = kido_root_override {
        let root_value = root.to_string_lossy();
        output.push_str(&format!(
            "Environment=\"KIDOBO_ROOT={}\"\n",
            escape_systemd_value(root_value.as_ref())
        ));
    }

    let executable = executable_path.to_string_lossy();
    output.push_str(&format!(
        "ExecStart=\"{}\" sync\n",
        escape_systemd_value(executable.as_ref())
    ));

    output
}

fn escape_systemd_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }

    escaped
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

    use super::{
        DEFAULT_BLOCKLIST_TEMPLATE, DEFAULT_CONFIG_TEMPLATE, DEFAULT_SYSTEMD_DIR,
        DEFAULT_SYSTEMD_TIMER_TEMPLATE, KIDOBO_SYNC_SERVICE_FILE, KIDOBO_SYNC_TIMER_FILE,
        build_systemd_service_template, infer_kido_root_override, resolve_systemd_dir,
        run_init_with_paths,
    };
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
        let systemd_dir = temp.path().join("systemd/system");
        let service_file = systemd_dir.join(KIDOBO_SYNC_SERVICE_FILE);
        let timer_file = systemd_dir.join(KIDOBO_SYNC_TIMER_FILE);

        run_init_with_paths(&paths).expect("init");

        assert!(paths.config_dir.exists());
        assert!(paths.data_dir.exists());
        assert!(paths.remote_cache_dir.exists());
        assert!(paths.lock_file.exists());

        let config = fs::read_to_string(&paths.config_file).expect("config");
        assert_eq!(config, DEFAULT_CONFIG_TEMPLATE);

        let blocklist = fs::read_to_string(&paths.blocklist_file).expect("blocklist");
        assert_eq!(blocklist, DEFAULT_BLOCKLIST_TEMPLATE);

        let service = fs::read_to_string(service_file).expect("service");
        let expected_service =
            build_systemd_service_template(Path::new("/usr/local/bin/kidobo"), Some(temp.path()));
        assert_eq!(service, expected_service);

        let timer = fs::read_to_string(timer_file).expect("timer");
        assert_eq!(timer, DEFAULT_SYSTEMD_TIMER_TEMPLATE);
    }

    #[test]
    fn init_does_not_overwrite_existing_files() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        let systemd_dir = temp.path().join("systemd/system");
        let service_file = systemd_dir.join(KIDOBO_SYNC_SERVICE_FILE);
        let timer_file = systemd_dir.join(KIDOBO_SYNC_TIMER_FILE);

        fs::create_dir_all(&paths.config_dir).expect("mkdir config");
        fs::create_dir_all(&paths.data_dir).expect("mkdir data");
        fs::create_dir_all(&paths.cache_dir).expect("mkdir cache");
        fs::create_dir_all(&systemd_dir).expect("mkdir systemd");
        fs::write(&paths.config_file, "custom-config").expect("write config");
        fs::write(&paths.blocklist_file, "custom-blocklist").expect("write blocklist");
        fs::write(&paths.lock_file, "custom-lock").expect("write lock");
        fs::write(&service_file, "custom-service").expect("write service");
        fs::write(&timer_file, "custom-timer").expect("write timer");

        run_init_with_paths(&paths).expect("init");

        let config = fs::read_to_string(&paths.config_file).expect("config");
        assert_eq!(config, "custom-config");

        let blocklist = fs::read_to_string(&paths.blocklist_file).expect("blocklist");
        assert_eq!(blocklist, "custom-blocklist");

        let lock_file = fs::read_to_string(&paths.lock_file).expect("lock");
        assert_eq!(lock_file, "custom-lock");

        let service = fs::read_to_string(service_file).expect("service");
        assert_eq!(service, "custom-service");

        let timer = fs::read_to_string(timer_file).expect("timer");
        assert_eq!(timer, "custom-timer");
    }

    #[test]
    fn init_handles_repeated_runs_idempotently() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        let systemd_dir = temp.path().join("systemd/system");

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
        assert_eq!(
            fs::read_to_string(systemd_dir.join(KIDOBO_SYNC_TIMER_FILE)).expect("timer"),
            DEFAULT_SYSTEMD_TIMER_TEMPLATE
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

    #[test]
    fn infer_root_override_uses_kidobo_root_layout_only() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        let inferred = infer_kido_root_override(&paths).expect("inferred root");
        assert_eq!(inferred, temp.path());

        let system_paths = ResolvedPaths {
            config_dir: PathBuf::from("/etc/kidobo"),
            config_file: PathBuf::from("/etc/kidobo/config.toml"),
            data_dir: PathBuf::from("/var/lib/kidobo"),
            blocklist_file: PathBuf::from("/var/lib/kidobo/blocklist.txt"),
            cache_dir: PathBuf::from("/var/cache/kidobo"),
            remote_cache_dir: PathBuf::from("/var/cache/kidobo/remote"),
            lock_file: PathBuf::from("/var/cache/kidobo/sync.lock"),
        };
        assert_eq!(infer_kido_root_override(&system_paths), None);
    }

    #[test]
    fn resolve_systemd_dir_uses_default_when_no_root_override() {
        assert_eq!(resolve_systemd_dir(None), Path::new(DEFAULT_SYSTEMD_DIR));
    }

    #[test]
    fn systemd_service_template_includes_optional_kido_root() {
        let without_root = build_systemd_service_template(Path::new("/usr/local/bin/kidobo"), None);
        assert!(!without_root.contains("KIDOBO_ROOT="));
        assert!(without_root.contains("ExecStart=\"/usr/local/bin/kidobo\" sync"));

        let with_root = build_systemd_service_template(
            Path::new("/usr/local/bin/kidobo"),
            Some(Path::new("/tmp/kidobo-root")),
        );
        assert!(with_root.contains("Environment=\"KIDOBO_ROOT=/tmp/kidobo-root\""));
    }
}
