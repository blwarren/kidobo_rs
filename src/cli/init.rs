use std::env;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};

use crate::adapters::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, SudoCommandRunner,
};
use crate::adapters::path::{
    ENV_KIDOBO_ROOT, PathResolutionInput, ResolvedPaths, resolve_paths_for_init,
};
use crate::error::KidoboError;

const DEFAULT_CONFIG_TEMPLATE: &str = r#"[ipset]
set_name = "kidobo"
chain_action = "DROP"

[safe]
ips = []
include_github_meta = true
github_meta_url = "https://api.github.com/meta"
# github_meta_categories = ["api", "git", "hooks", "packages"]

[remote]
timeout_secs = 30
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

#[cfg(test)]
const INIT_FILE_READ_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProvisionState {
    Created,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct InitSummary {
    created: Vec<PathBuf>,
    unchanged: Vec<PathBuf>,
}

impl InitSummary {
    fn record(&mut self, path: &Path, state: ProvisionState) {
        match state {
            ProvisionState::Created => self.created.push(path.to_path_buf()),
            ProvisionState::Unchanged => self.unchanged.push(path.to_path_buf()),
        }
    }
}

trait InitCommandRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> InitCommandRunner for SudoCommandRunner<E> {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        SudoCommandRunner::run(self, command, args)
    }
}

#[cfg(test)]
struct NoopInitCommandRunner;

#[cfg(test)]
impl InitCommandRunner for NoopInitCommandRunner {
    fn run(&self, _command: &str, _args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        Ok(CommandResult {
            status: Some(0),
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

#[allow(clippy::print_stdout)]
pub fn run_init_command() -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths_for_init(&path_input)?;
    let executable_path =
        env::current_exe().unwrap_or_else(|_| PathBuf::from(DEFAULT_KIDOBO_BINARY_PATH));
    let kido_root_override = path_input.env.get(ENV_KIDOBO_ROOT).map(PathBuf::from);
    let sudo_runner = SudoCommandRunner::default();
    let summary = run_init_with_context(
        &paths,
        &executable_path,
        kido_root_override.as_deref(),
        &sudo_runner,
    )?;
    print_init_summary(&summary);
    Ok(())
}

#[cfg(test)]
pub(crate) fn run_init_with_paths(paths: &ResolvedPaths) -> Result<(), KidoboError> {
    let _ = run_init_with_paths_with_summary(paths)?;
    Ok(())
}

#[cfg(test)]
fn run_init_with_paths_with_summary(paths: &ResolvedPaths) -> Result<InitSummary, KidoboError> {
    let kido_root_override = infer_kido_root_override(paths);
    run_init_with_paths_and_runner(paths, &NoopInitCommandRunner, kido_root_override.as_deref())
}

#[cfg(test)]
fn run_init_with_paths_and_runner(
    paths: &ResolvedPaths,
    runner: &dyn InitCommandRunner,
    kido_root_override: Option<&Path>,
) -> Result<InitSummary, KidoboError> {
    let executable_path = PathBuf::from(DEFAULT_KIDOBO_BINARY_PATH);
    run_init_with_context(paths, &executable_path, kido_root_override, runner)
}

fn run_init_with_context(
    paths: &ResolvedPaths,
    executable_path: &Path,
    kido_root_override: Option<&Path>,
    runner: &dyn InitCommandRunner,
) -> Result<InitSummary, KidoboError> {
    let mut summary = InitSummary::default();
    let systemd_dir = resolve_systemd_dir(kido_root_override);
    let systemd_service = systemd_dir.join(KIDOBO_SYNC_SERVICE_FILE);
    let systemd_timer = systemd_dir.join(KIDOBO_SYNC_TIMER_FILE);

    for dir in [
        &paths.config_dir,
        &paths.data_dir,
        &paths.remote_cache_dir,
        &systemd_dir,
    ] {
        summary.record(dir, ensure_dir(dir)?);
    }

    let service_template = build_systemd_service_template(executable_path, kido_root_override);
    for (file_path, contents) in [
        (&paths.config_file, DEFAULT_CONFIG_TEMPLATE),
        (&paths.blocklist_file, DEFAULT_BLOCKLIST_TEMPLATE),
        (&paths.lock_file, ""),
        (&systemd_service, service_template.as_str()),
        (&systemd_timer, DEFAULT_SYSTEMD_TIMER_TEMPLATE),
    ] {
        summary.record(file_path, ensure_file_if_missing(file_path, contents)?);
    }

    if kido_root_override.is_none() {
        ensure_systemd_timer_enabled(runner)?;
    }

    Ok(summary)
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

    let _ = writeln!(&mut output, "Environment=\"KIDOBO_LOG_FORMAT=journal\"");

    if let Some(root) = kido_root_override {
        let root_value = root.to_string_lossy();
        let _ = writeln!(
            &mut output,
            "Environment=\"KIDOBO_ROOT={}\"",
            escape_systemd_value(root_value.as_ref())
        );
    }

    let executable = executable_path.to_string_lossy();
    let _ = writeln!(
        &mut output,
        "ExecStart=\"{}\" sync",
        escape_systemd_value(executable.as_ref())
    );

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

#[allow(clippy::print_stdout)]
fn print_init_summary(summary: &InitSummary) {
    print!("{}", render_init_summary(summary));
}

fn render_init_summary(summary: &InitSummary) -> String {
    let mut output = String::new();
    let _ = writeln!(
        &mut output,
        "init completed: created={} unchanged={}",
        summary.created.len(),
        summary.unchanged.len()
    );
    for path in &summary.created {
        let _ = writeln!(&mut output, "created: {}", path.display());
    }
    for path in &summary.unchanged {
        let _ = writeln!(&mut output, "unchanged: {}", path.display());
    }
    output
}

fn ensure_systemd_timer_enabled(runner: &dyn InitCommandRunner) -> Result<(), KidoboError> {
    run_required_systemd_command(runner, &["daemon-reload"])?;
    run_required_systemd_command(runner, &["reset-failed", KIDOBO_SYNC_SERVICE_FILE])?;
    run_required_systemd_command(runner, &["enable", "--now", KIDOBO_SYNC_TIMER_FILE])?;
    Ok(())
}

fn run_required_systemd_command(
    runner: &dyn InitCommandRunner,
    args: &[&str],
) -> Result<(), KidoboError> {
    let command = format!("systemctl {}", args.join(" "));
    let result = runner
        .run("systemctl", args)
        .map_err(|err| KidoboError::InitSystemd {
            command: command.clone(),
            reason: err.to_string(),
        })?;

    if result.success {
        return Ok(());
    }

    let stderr = result.stderr.trim();
    let stdout = result.stdout.trim();
    let reason = if !stderr.is_empty() {
        format!("status={:?} stderr={stderr}", result.status)
    } else if !stdout.is_empty() {
        format!("status={:?} stdout={stdout}", result.status)
    } else {
        format!("status={:?}", result.status)
    };

    Err(KidoboError::InitSystemd { command, reason })
}

fn ensure_dir(path: &Path) -> Result<ProvisionState, KidoboError> {
    let existed = path.exists();
    fs::create_dir_all(path).map_err(|err| KidoboError::InitIo {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;

    if existed {
        Ok(ProvisionState::Unchanged)
    } else {
        Ok(ProvisionState::Created)
    }
}

fn ensure_file_if_missing(path: &Path, contents: &str) -> Result<ProvisionState, KidoboError> {
    if path.exists() {
        return Ok(ProvisionState::Unchanged);
    }

    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }

    fs::write(path, contents).map_err(|err| KidoboError::InitIo {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;

    Ok(ProvisionState::Created)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{
        CommandResult, CommandRunnerError, DEFAULT_BLOCKLIST_TEMPLATE, DEFAULT_CONFIG_TEMPLATE,
        DEFAULT_SYSTEMD_DIR, DEFAULT_SYSTEMD_TIMER_TEMPLATE, INIT_FILE_READ_LIMIT,
        InitCommandRunner, KIDOBO_SYNC_SERVICE_FILE, KIDOBO_SYNC_TIMER_FILE,
        build_systemd_service_template, ensure_systemd_timer_enabled, infer_kido_root_override,
        render_init_summary, resolve_systemd_dir, run_init_with_paths,
        run_init_with_paths_and_runner, run_init_with_paths_with_summary,
    };
    use crate::adapters::limited_io::read_to_string_with_limit;
    use crate::adapters::path::ResolvedPaths;
    use crate::error::KidoboError;

    struct MockInitCommandRunner {
        responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
        invocations: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl MockInitCommandRunner {
        fn new(responses: Vec<Result<CommandResult, CommandRunnerError>>) -> Self {
            Self {
                responses: RefCell::new(VecDeque::from(responses)),
                invocations: RefCell::new(Vec::new()),
            }
        }

        fn invocations(&self) -> Vec<(String, Vec<String>)> {
            self.invocations.borrow().clone()
        }
    }

    impl InitCommandRunner for MockInitCommandRunner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            self.invocations.borrow_mut().push((
                command.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued response")
        }
    }

    fn success_result() -> CommandResult {
        CommandResult {
            status: Some(0),
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn failed_result(status: i32, stderr: &str) -> CommandResult {
        CommandResult {
            status: Some(status),
            success: false,
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

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

        let config =
            read_to_string_with_limit(&paths.config_file, INIT_FILE_READ_LIMIT).expect("config");
        assert_eq!(config, DEFAULT_CONFIG_TEMPLATE);

        let blocklist = read_to_string_with_limit(&paths.blocklist_file, INIT_FILE_READ_LIMIT)
            .expect("blocklist");
        assert_eq!(blocklist, DEFAULT_BLOCKLIST_TEMPLATE);

        let service =
            read_to_string_with_limit(&service_file, INIT_FILE_READ_LIMIT).expect("service");
        let expected_service =
            build_systemd_service_template(Path::new("/usr/local/bin/kidobo"), Some(temp.path()));
        assert_eq!(service, expected_service);

        let timer = read_to_string_with_limit(&timer_file, INIT_FILE_READ_LIMIT).expect("timer");
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

        let config =
            read_to_string_with_limit(&paths.config_file, INIT_FILE_READ_LIMIT).expect("config");
        assert_eq!(config, "custom-config");

        let blocklist = read_to_string_with_limit(&paths.blocklist_file, INIT_FILE_READ_LIMIT)
            .expect("blocklist");
        assert_eq!(blocklist, "custom-blocklist");

        let lock_file =
            read_to_string_with_limit(&paths.lock_file, INIT_FILE_READ_LIMIT).expect("lock");
        assert_eq!(lock_file, "custom-lock");

        let service =
            read_to_string_with_limit(&service_file, INIT_FILE_READ_LIMIT).expect("service");
        assert_eq!(service, "custom-service");

        let timer = read_to_string_with_limit(&timer_file, INIT_FILE_READ_LIMIT).expect("timer");
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
            read_to_string_with_limit(&paths.config_file, INIT_FILE_READ_LIMIT).expect("config"),
            DEFAULT_CONFIG_TEMPLATE
        );
        assert_eq!(
            read_to_string_with_limit(&paths.blocklist_file, INIT_FILE_READ_LIMIT)
                .expect("blocklist"),
            DEFAULT_BLOCKLIST_TEMPLATE
        );
        assert_eq!(
            read_to_string_with_limit(
                systemd_dir.join(KIDOBO_SYNC_TIMER_FILE).as_ref(),
                INIT_FILE_READ_LIMIT
            )
            .expect("timer"),
            DEFAULT_SYSTEMD_TIMER_TEMPLATE
        );
    }

    #[test]
    fn init_summary_tracks_created_vs_unchanged_paths() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        let first = run_init_with_paths_with_summary(&paths).expect("first init");
        assert_eq!(first.created.len(), 9);
        assert!(first.unchanged.is_empty());
        assert!(first.created.contains(&paths.config_dir));
        assert!(first.created.contains(&paths.config_file));
        assert!(first.created.contains(&paths.remote_cache_dir));

        let second = run_init_with_paths_with_summary(&paths).expect("second init");
        assert!(second.created.is_empty());
        assert_eq!(second.unchanged.len(), 9);
        assert!(second.unchanged.contains(&paths.config_dir));
        assert!(second.unchanged.contains(&paths.config_file));
        assert!(second.unchanged.contains(&paths.remote_cache_dir));
    }

    #[test]
    fn init_summary_render_is_deterministic() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        let first = run_init_with_paths_with_summary(&paths).expect("first init");
        let rendered = render_init_summary(&first);

        assert!(rendered.starts_with("init completed: created=9 unchanged=0\n"));
        assert!(rendered.contains(&format!("created: {}\n", paths.config_dir.display())));
        assert!(rendered.contains(&format!("created: {}\n", paths.config_file.display())));
    }

    #[test]
    fn init_skips_systemctl_when_kidobo_root_is_set() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        let runner = MockInitCommandRunner::new(Vec::new());

        run_init_with_paths_and_runner(&paths, &runner, Some(temp.path())).expect("init");
        assert!(runner.invocations().is_empty());
    }

    #[test]
    fn ensure_systemd_timer_enabled_runs_required_commands_in_order() {
        let runner = MockInitCommandRunner::new(vec![
            Ok(success_result()),
            Ok(success_result()),
            Ok(success_result()),
        ]);

        ensure_systemd_timer_enabled(&runner).expect("systemd setup");

        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[0].0, "systemctl");
        assert_eq!(invocations[0].1, vec!["daemon-reload"]);
        assert_eq!(invocations[1].0, "systemctl");
        assert_eq!(
            invocations[1].1,
            vec!["reset-failed", KIDOBO_SYNC_SERVICE_FILE]
        );
        assert_eq!(invocations[2].0, "systemctl");
        assert_eq!(
            invocations[2].1,
            vec!["enable", "--now", KIDOBO_SYNC_TIMER_FILE]
        );
    }

    #[test]
    fn ensure_systemd_timer_enabled_surfaces_nonzero_exit() {
        let runner = MockInitCommandRunner::new(vec![
            Ok(success_result()),
            Ok(success_result()),
            Ok(failed_result(1, "failed to enable unit")),
        ]);

        let err = ensure_systemd_timer_enabled(&runner).expect_err("must fail");
        match err {
            KidoboError::InitSystemd { command, reason } => {
                assert_eq!(
                    command,
                    format!("systemctl enable --now {KIDOBO_SYNC_TIMER_FILE}")
                );
                assert!(reason.contains("status=Some(1)"));
                assert!(reason.contains("failed to enable unit"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn ensure_systemd_timer_enabled_surfaces_runner_errors() {
        let runner = MockInitCommandRunner::new(vec![Err(CommandRunnerError::Spawn {
            command: "sudo systemctl daemon-reload".to_string(),
            reason: "command not found".to_string(),
        })]);

        let err = ensure_systemd_timer_enabled(&runner).expect_err("must fail");
        match err {
            KidoboError::InitSystemd { command, reason } => {
                assert_eq!(command, "systemctl daemon-reload");
                assert!(reason.contains("command not found"));
            }
            _ => panic!("unexpected error variant"),
        }
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
        assert!(without_root.contains("Environment=\"KIDOBO_LOG_FORMAT=journal\""));
        assert!(without_root.contains("ExecStart=\"/usr/local/bin/kidobo\" sync"));

        let with_root = build_systemd_service_template(
            Path::new("/usr/local/bin/kidobo"),
            Some(Path::new("/tmp/kidobo-root")),
        );
        assert!(with_root.contains("Environment=\"KIDOBO_LOG_FORMAT=journal\""));
        assert!(with_root.contains("Environment=\"KIDOBO_ROOT=/tmp/kidobo-root\""));
    }
}
