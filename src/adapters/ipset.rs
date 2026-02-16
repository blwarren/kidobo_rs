use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use log::warn;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::adapters::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, SudoCommandRunner,
};

const IPSET_NAME_MAX_LEN: usize = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsetFamily {
    Inet,
    Inet6,
}

impl IpsetFamily {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inet => "inet",
            Self::Inet6 => "inet6",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsetSetSpec {
    pub set_name: String,
    pub set_type: String,
    pub family: IpsetFamily,
    pub hashsize: u32,
    pub maxelem: u32,
    pub timeout: u32,
}

#[derive(Debug, Error)]
pub enum IpsetError {
    #[error("ipset command execution failed: {source}")]
    CommandExecution {
        #[from]
        source: CommandRunnerError,
    },

    #[error("ipset command failed `{command}` with status {status:?}: {stderr}")]
    CommandFailed {
        command: String,
        status: Option<i32>,
        stderr: String,
    },

    #[error("failed to write ipset restore script {path}: {reason}")]
    WriteRestoreScript { path: PathBuf, reason: String },

    #[error("failed to create ipset restore script {path}: {reason}")]
    CreateRestoreScript { path: PathBuf, reason: String },
}

pub trait IpsetCommandRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> IpsetCommandRunner for SudoCommandRunner<E> {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        SudoCommandRunner::run(self, command, args)
    }
}

pub fn ipset_exists(runner: &dyn IpsetCommandRunner, set_name: &str) -> Result<bool, IpsetError> {
    let result = runner.run("ipset", &["list", set_name])?;
    if result.success {
        return Ok(true);
    }

    if is_missing_set_result(&result) {
        return Ok(false);
    }

    Err(IpsetError::CommandFailed {
        command: format!("ipset list {set_name}"),
        status: result.status,
        stderr: result.stderr,
    })
}

pub fn ensure_ipset_exists(
    runner: &dyn IpsetCommandRunner,
    spec: &IpsetSetSpec,
) -> Result<(), IpsetError> {
    if ipset_exists(runner, &spec.set_name)? {
        return Ok(());
    }

    create_ipset(runner, spec)
}

pub fn create_ipset(
    runner: &dyn IpsetCommandRunner,
    spec: &IpsetSetSpec,
) -> Result<(), IpsetError> {
    let hashsize = spec.hashsize.to_string();
    let maxelem = spec.maxelem.to_string();
    let timeout = spec.timeout.to_string();

    run_checked(
        runner,
        "ipset",
        &[
            "create",
            &spec.set_name,
            &spec.set_type,
            "family",
            spec.family.as_str(),
            "hashsize",
            &hashsize,
            "maxelem",
            &maxelem,
            "timeout",
            &timeout,
            "-exist",
        ],
    )?;

    Ok(())
}

pub fn generate_temp_set_name(base_set_name: &str) -> String {
    let suffix = random_hex_suffix(8);
    let max_base_len = IPSET_NAME_MAX_LEN.saturating_sub(suffix.len() + 1);
    let mut base = truncate_to_max_bytes(base_set_name, max_base_len).to_string();
    if base.is_empty() {
        base = "kidobo".to_string();
    }

    let candidate = format!("{base}-{suffix}");
    if candidate.len() <= IPSET_NAME_MAX_LEN {
        candidate
    } else {
        truncate_to_max_bytes(&candidate, IPSET_NAME_MAX_LEN).to_string()
    }
}

pub fn build_restore_script(
    spec: &IpsetSetSpec,
    temp_set_name: &str,
    entries: &[String],
) -> String {
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort();
    sorted_entries.dedup();

    let mut script = String::new();
    script.push_str(&format!(
        "create {} {} family {} hashsize {} maxelem {} timeout {}\n",
        temp_set_name,
        spec.set_type,
        spec.family.as_str(),
        spec.hashsize,
        spec.maxelem,
        spec.timeout
    ));

    for entry in sorted_entries {
        script.push_str(&format!("add {} {}\n", temp_set_name, entry));
    }

    script.push_str(&format!("swap {} {}\n", temp_set_name, spec.set_name));
    script
}

pub fn execute_ipset_restore(
    runner: &dyn IpsetCommandRunner,
    script: &str,
) -> Result<(), IpsetError> {
    let (mut file, path) = create_restore_script_file()?;
    file.write_all(script.as_bytes())
        .and_then(|_| file.flush())
        .map_err(|err| IpsetError::WriteRestoreScript {
            path: path.clone(),
            reason: err.to_string(),
        })?;
    drop(file);

    let path_string = path.display().to_string();
    let restore_result = run_checked(runner, "ipset", &["restore", "-file", &path_string]);

    if let Err(err) = fs::remove_file(&path) {
        warn!(
            "failed to remove temporary ipset restore script {}: {err}",
            path.display()
        );
    }

    restore_result.map(|_| ())
}

pub fn atomic_replace_ipset(
    runner: &dyn IpsetCommandRunner,
    spec: &IpsetSetSpec,
    entries: &[String],
) -> Result<(), IpsetError> {
    let temp_set_name = generate_temp_set_name(&spec.set_name);

    best_effort_destroy_set(runner, &temp_set_name);

    let script = build_restore_script(spec, &temp_set_name, entries);
    let restore_result = execute_ipset_restore(runner, &script);

    best_effort_destroy_set(runner, &temp_set_name);

    restore_result
}

fn run_checked(
    runner: &dyn IpsetCommandRunner,
    command: &str,
    args: &[&str],
) -> Result<CommandResult, IpsetError> {
    let result = runner.run(command, args)?;

    if result.success {
        return Ok(result);
    }

    Err(IpsetError::CommandFailed {
        command: display_command(command, args),
        status: result.status,
        stderr: result.stderr,
    })
}

fn best_effort_destroy_set(runner: &dyn IpsetCommandRunner, set_name: &str) {
    if let Err(err) = runner.run("ipset", &["destroy", set_name]) {
        warn!("best-effort ipset destroy for {set_name} failed: {err}");
    }
}

fn display_command(command: &str, args: &[&str]) -> String {
    if args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, args.join(" "))
    }
}

fn is_missing_set_result(result: &CommandResult) -> bool {
    result.status == Some(1)
        && result
            .stderr
            .to_ascii_lowercase()
            .contains("does not exist")
}

fn restore_script_path() -> PathBuf {
    env::temp_dir().join(format!("kidobo-ipset-{}.restore", random_hex_suffix(12)))
}

fn create_restore_script_file() -> Result<(std::fs::File, PathBuf), IpsetError> {
    for _ in 0..16 {
        let path = restore_script_path();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(IpsetError::CreateRestoreScript {
                    path,
                    reason: err.to_string(),
                });
            }
        }
    }

    let path = restore_script_path();
    Err(IpsetError::CreateRestoreScript {
        path,
        reason: "failed to create a unique temporary restore script path".to_string(),
    })
}

fn truncate_to_max_bytes(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }

    let mut idx = max_bytes;
    while idx > 0 && !input.is_char_boundary(idx) {
        idx -= 1;
    }
    &input[..idx]
}

fn random_hex_suffix(length: usize) -> String {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u128, |value| value.as_nanos());

    let seed = format!("{}-{now_nanos}", process::id());
    let digest = Sha256::digest(seed.as_bytes());

    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }

    hex[..length.min(hex.len())].to_string()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;

    use super::{
        IpsetCommandRunner, IpsetError, IpsetFamily, IpsetSetSpec, atomic_replace_ipset,
        build_restore_script, generate_temp_set_name, ipset_exists,
    };
    use crate::adapters::command_runner::{CommandResult, CommandRunnerError};

    struct MockRunner {
        responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
        invocations: RefCell<Vec<(String, Vec<String>)>>,
        restore_scripts: RefCell<Vec<String>>,
    }

    impl MockRunner {
        fn new(responses: Vec<Result<CommandResult, CommandRunnerError>>) -> Self {
            Self {
                responses: RefCell::new(VecDeque::from(responses)),
                invocations: RefCell::new(Vec::new()),
                restore_scripts: RefCell::new(Vec::new()),
            }
        }

        fn invocations(&self) -> Vec<(String, Vec<String>)> {
            self.invocations.borrow().clone()
        }

        fn restore_scripts(&self) -> Vec<String> {
            self.restore_scripts.borrow().clone()
        }
    }

    impl IpsetCommandRunner for MockRunner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            self.invocations.borrow_mut().push((
                command.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));

            if command == "ipset" && args.first() == Some(&"restore") && args.len() == 3 {
                let script = fs::read_to_string(args[2]).expect("restore script readable");
                self.restore_scripts.borrow_mut().push(script);
            }

            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued response")
        }
    }

    fn ok(status: i32) -> CommandResult {
        CommandResult {
            status: Some(status),
            success: status == 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn temp_set_name_is_capped_at_31_chars() {
        let name = generate_temp_set_name("kidobo-super-long-name-that-must-be-truncated");
        assert!(name.len() <= 31);
        assert!(name.contains('-'));
    }

    #[test]
    fn restore_script_is_deterministic_and_sorted() {
        let spec = IpsetSetSpec {
            set_name: "kidobo".to_string(),
            set_type: "hash:net".to_string(),
            family: IpsetFamily::Inet,
            hashsize: 65536,
            maxelem: 500000,
            timeout: 0,
        };

        let script = build_restore_script(
            &spec,
            "kidobo-temp",
            &[
                "203.0.113.0/24".to_string(),
                "10.0.0.0/24".to_string(),
                "203.0.113.0/24".to_string(),
            ],
        );

        assert_eq!(
            script,
            "create kidobo-temp hash:net family inet hashsize 65536 maxelem 500000 timeout 0\nadd kidobo-temp 10.0.0.0/24\nadd kidobo-temp 203.0.113.0/24\nswap kidobo-temp kidobo\n"
        );
    }

    #[test]
    fn ipset_exists_maps_missing_set_to_false() {
        let runner = MockRunner::new(vec![Ok(CommandResult {
            status: Some(1),
            success: false,
            stdout: String::new(),
            stderr: "The set with the given name does not exist".to_string(),
        })]);

        let exists = ipset_exists(&runner, "kidobo").expect("exists check");
        assert!(!exists);
    }

    #[test]
    fn ipset_exists_errors_on_unexpected_failure() {
        let runner = MockRunner::new(vec![Ok(CommandResult {
            status: Some(2),
            success: false,
            stdout: String::new(),
            stderr: "permission denied".to_string(),
        })]);

        let err = ipset_exists(&runner, "kidobo").expect_err("must fail");
        assert!(matches!(err, IpsetError::CommandFailed { .. }));
    }

    #[test]
    fn atomic_replace_runs_restore_swap_and_destroy_paths() {
        let runner = MockRunner::new(vec![
            Ok(ok(1)), // best-effort stale temp destroy
            Ok(ok(0)), // restore
            Ok(ok(0)), // final destroy
        ]);

        let spec = IpsetSetSpec {
            set_name: "kidobo".to_string(),
            set_type: "hash:net".to_string(),
            family: IpsetFamily::Inet,
            hashsize: 65536,
            maxelem: 500000,
            timeout: 0,
        };

        atomic_replace_ipset(
            &runner,
            &spec,
            &["198.51.100.7/32".to_string(), "10.0.0.0/24".to_string()],
        )
        .expect("atomic replace");

        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[0].0, "ipset");
        assert_eq!(invocations[0].1[0], "destroy");
        assert_eq!(invocations[1].1[0], "restore");
        assert_eq!(invocations[1].1[1], "-file");
        assert_eq!(invocations[2].1[0], "destroy");

        let scripts = runner.restore_scripts();
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].contains("create"));
        assert!(scripts[0].contains("swap"));
        assert!(scripts[0].contains("add"));
    }

    #[test]
    fn atomic_replace_attempts_final_destroy_after_restore_failure() {
        let runner = MockRunner::new(vec![
            Ok(ok(0)), // best-effort stale temp destroy
            Ok(CommandResult {
                status: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "restore failed".to_string(),
            }),
            Ok(ok(0)), // final destroy still attempted
        ]);

        let spec = IpsetSetSpec {
            set_name: "kidobo".to_string(),
            set_type: "hash:net".to_string(),
            family: IpsetFamily::Inet,
            hashsize: 65536,
            maxelem: 500000,
            timeout: 0,
        };

        let err = atomic_replace_ipset(&runner, &spec, &["10.0.0.0/24".to_string()])
            .expect_err("must fail");
        assert!(matches!(err, IpsetError::CommandFailed { .. }));

        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[2].1[0], "destroy");
    }

    #[test]
    fn create_restore_script_file_uses_restrictive_permissions() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let (file, path) = super::create_restore_script_file().expect("create temp script");
            drop(file);

            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);

            fs::remove_file(path).expect("cleanup");
        }
    }
}
