use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use log::info;
use serde::Serialize;

use crate::adapters::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, SudoCommandRunner,
};
use crate::adapters::config::load_config_from_file;
use crate::adapters::path::{PathResolutionInput, resolve_paths};
use crate::core::config::Config;
use crate::error::KidoboError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DoctorOverall {
    #[serde(rename = "OK")]
    Ok,
    #[serde(rename = "FAIL")]
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DoctorCheckStatus {
    #[serde(rename = "OK")]
    Ok,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "SKIP")]
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: DoctorCheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub overall: DoctorOverall,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let overall = if checks
            .iter()
            .any(|check| check.status == DoctorCheckStatus::Fail)
        {
            DoctorOverall::Fail
        } else {
            DoctorOverall::Ok
        };

        Self { overall, checks }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv6Mode {
    Enabled,
    Disabled,
    Unknown,
}

pub trait BinaryLocator {
    fn find_in_path(&self, binary: &str) -> Option<PathBuf>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemBinaryLocator;

impl BinaryLocator for SystemBinaryLocator {
    fn find_in_path(&self, binary: &str) -> Option<PathBuf> {
        find_binary_in_path(binary, env::var_os("PATH"))
    }
}

pub trait SudoProbeRunner {
    fn run_probe(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> SudoProbeRunner for SudoCommandRunner<E> {
    fn run_probe(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        self.run(command, args)
    }
}

#[allow(clippy::print_stdout)]
pub fn run_doctor_command() -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let binary_locator = SystemBinaryLocator;
    let sudo_runner = SudoCommandRunner::default();

    let report = build_doctor_report(&path_input, &binary_locator, &sudo_runner);
    let json = serde_json::to_string_pretty(&report).map_err(|err| {
        KidoboError::DoctorReportSerialize {
            reason: err.to_string(),
        }
    })?;

    println!("{json}");
    info!("doctor report: {json}");

    if report.overall == DoctorOverall::Ok {
        Ok(())
    } else {
        Err(KidoboError::DoctorFailed)
    }
}

pub(crate) fn build_doctor_report(
    path_input: &PathResolutionInput,
    binary_locator: &dyn BinaryLocator,
    sudo_probe_runner: &dyn SudoProbeRunner,
) -> DoctorReport {
    let mut checks = Vec::new();
    let mut binary_available = BTreeMap::new();

    let paths_result = resolve_paths(path_input);
    let mut config: Option<Config> = None;

    match &paths_result {
        Ok(paths) => match load_config_from_file(&paths.config_file) {
            Ok(parsed) => {
                checks.push(ok_check(
                    "config_parse",
                    format!("config parsed: {}", paths.config_file.display()),
                ));
                config = Some(parsed);
            }
            Err(err) => checks.push(fail_check(
                "config_parse",
                format!("failed to parse {}: {err}", paths.config_file.display()),
            )),
        },
        Err(err) => checks.push(fail_check(
            "config_parse",
            format!("path resolution failed: {err}"),
        )),
    }

    let ipv6_mode = match config.as_ref() {
        Some(cfg) if cfg.ipset.enable_ipv6 => Ipv6Mode::Enabled,
        Some(_) => Ipv6Mode::Disabled,
        None => Ipv6Mode::Unknown,
    };

    for (check_name, binary) in [
        ("binary_sudo", "sudo"),
        ("binary_ipset", "ipset"),
        ("binary_iptables", "iptables"),
        ("binary_iptables_save", "iptables-save"),
        ("binary_iptables_restore", "iptables-restore"),
    ] {
        let available = push_binary_check(&mut checks, binary_locator, check_name, binary);
        binary_available.insert(binary.to_string(), available);
    }

    match ipv6_mode {
        Ipv6Mode::Enabled => {
            let available =
                push_binary_check(&mut checks, binary_locator, "binary_ip6tables", "ip6tables");
            binary_available.insert("ip6tables".to_string(), available);
        }
        Ipv6Mode::Disabled => {
            checks.push(skip_check("binary_ip6tables", "ipv6 disabled in config"));
            binary_available.insert("ip6tables".to_string(), false);
        }
        Ipv6Mode::Unknown => {
            checks.push(skip_check(
                "binary_ip6tables",
                "config unavailable; ipv6 state unknown",
            ));
            binary_available.insert("ip6tables".to_string(), false);
        }
    }

    match &paths_result {
        Ok(paths) => {
            checks.push(file_exists_check("file_config", &paths.config_file));
            checks.push(file_exists_check("file_blocklist", &paths.blocklist_file));
            checks.push(cache_writability_check(&paths.remote_cache_dir));
        }
        Err(err) => {
            checks.push(fail_check(
                "file_config",
                format!("path resolution unavailable: {err}"),
            ));
            checks.push(fail_check(
                "file_blocklist",
                format!("path resolution unavailable: {err}"),
            ));
            checks.push(fail_check(
                "cache_writable",
                format!("path resolution unavailable: {err}"),
            ));
        }
    }

    let sudo_available = *binary_available.get("sudo").unwrap_or(&false);

    for (check_name, binary, args) in [
        ("sudo_probe_ipset", "ipset", vec!["list"]),
        ("sudo_probe_iptables", "iptables", vec!["-S"]),
        ("sudo_probe_iptables_save", "iptables-save", Vec::new()),
        (
            "sudo_probe_iptables_restore",
            "iptables-restore",
            vec!["--version"],
        ),
    ] {
        checks.push(sudo_probe_check(
            check_name,
            binary,
            &args,
            sudo_available,
            &binary_available,
            sudo_probe_runner,
        ));
    }

    let ipv6_probe = match ipv6_mode {
        Ipv6Mode::Enabled => sudo_probe_check(
            "sudo_probe_ip6tables",
            "ip6tables",
            &["-S"],
            sudo_available,
            &binary_available,
            sudo_probe_runner,
        ),
        Ipv6Mode::Disabled => skip_check("sudo_probe_ip6tables", "ipv6 disabled in config"),
        Ipv6Mode::Unknown => skip_check(
            "sudo_probe_ip6tables",
            "config unavailable; ipv6 state unknown",
        ),
    };
    checks.push(ipv6_probe);

    DoctorReport::from_checks(checks)
}

fn push_binary_check(
    checks: &mut Vec<DoctorCheck>,
    locator: &dyn BinaryLocator,
    check_name: &'static str,
    binary: &str,
) -> bool {
    match locator.find_in_path(binary) {
        Some(path) => {
            checks.push(ok_check(
                check_name,
                format!("found on PATH: {}", path.display()),
            ));
            true
        }
        None => {
            checks.push(fail_check(
                check_name,
                format!("{binary} not found on PATH"),
            ));
            false
        }
    }
}

fn file_exists_check(check_name: &'static str, path: &Path) -> DoctorCheck {
    if path.exists() {
        ok_check(check_name, format!("exists: {}", path.display()))
    } else {
        fail_check(check_name, format!("missing: {}", path.display()))
    }
}

fn cache_writability_check(remote_cache_dir: &Path) -> DoctorCheck {
    match ensure_cache_writable(remote_cache_dir) {
        Ok(()) => ok_check(
            "cache_writable",
            format!("remote cache writable: {}", remote_cache_dir.display()),
        ),
        Err(reason) => fail_check(
            "cache_writable",
            format!(
                "remote cache not writable at {}: {reason}",
                remote_cache_dir.display()
            ),
        ),
    }
}

fn ensure_cache_writable(remote_cache_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(remote_cache_dir).map_err(|err| err.to_string())?;

    let probe_path = remote_cache_dir.join(format!(".doctor-write-test-{}", std::process::id()));
    fs::write(&probe_path, b"kidobo").map_err(|err| err.to_string())?;
    fs::remove_file(&probe_path).map_err(|err| err.to_string())
}

fn sudo_probe_check(
    check_name: &'static str,
    binary: &str,
    args: &[&str],
    sudo_available: bool,
    binary_available: &BTreeMap<String, bool>,
    runner: &dyn SudoProbeRunner,
) -> DoctorCheck {
    if !sudo_available {
        return skip_check(check_name, "sudo binary is unavailable");
    }

    if !binary_available.get(binary).copied().unwrap_or(false) {
        return skip_check(check_name, format!("{binary} binary is unavailable"));
    }

    let command = display_command(binary, args);
    match runner.run_probe(binary, args) {
        Ok(result) if result.success => {
            ok_check(check_name, format!("sudo -n {command} succeeded"))
        }
        Ok(result) => fail_check(
            check_name,
            format!(
                "sudo -n {command} failed with status {:?}: {}",
                result.status,
                stderr_detail(&result.stderr)
            ),
        ),
        Err(err) => fail_check(
            check_name,
            format!("sudo -n {command} execution failed: {err}"),
        ),
    }
}

fn display_command(binary: &str, args: &[&str]) -> String {
    if args.is_empty() {
        binary.to_string()
    } else {
        format!("{} {}", binary, args.join(" "))
    }
}

fn stderr_detail(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        "no stderr".to_string()
    } else {
        trimmed.to_string()
    }
}

fn ok_check(name: &'static str, detail: String) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: DoctorCheckStatus::Ok,
        detail,
    }
}

fn fail_check(name: &'static str, detail: String) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: DoctorCheckStatus::Fail,
        detail,
    }
}

fn skip_check(name: &'static str, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: DoctorCheckStatus::Skip,
        detail: detail.into(),
    }
}

fn find_binary_in_path(binary: &str, path: Option<OsString>) -> Option<PathBuf> {
    let path = path?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{
        BinaryLocator, DoctorCheck, DoctorCheckStatus, DoctorOverall, SudoProbeRunner,
        build_doctor_report,
    };
    use crate::adapters::command_runner::{CommandResult, CommandRunnerError};
    use crate::adapters::path::{ENV_KIDOBO_ROOT, PathResolutionInput};

    struct MockBinaryLocator {
        availability: BTreeMap<String, bool>,
    }

    impl MockBinaryLocator {
        fn new(available: &[&str]) -> Self {
            let mut availability = BTreeMap::new();
            for binary in available {
                availability.insert((*binary).to_string(), true);
            }
            Self { availability }
        }
    }

    impl BinaryLocator for MockBinaryLocator {
        fn find_in_path(&self, binary: &str) -> Option<PathBuf> {
            if self.availability.get(binary).copied().unwrap_or(false) {
                Some(PathBuf::from(format!("/mock/bin/{binary}")))
            } else {
                None
            }
        }
    }

    struct MockProbeRunner {
        responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
        invocations: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl MockProbeRunner {
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

    impl SudoProbeRunner for MockProbeRunner {
        fn run_probe(
            &self,
            command: &str,
            args: &[&str],
        ) -> Result<CommandResult, CommandRunnerError> {
            self.invocations.borrow_mut().push((
                command.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued probe response")
        }
    }

    fn path_input_for_root(root: &Path) -> PathResolutionInput {
        let mut env = BTreeMap::new();
        env.insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());
        PathResolutionInput {
            explicit_config_path: None,
            cwd: Some(root.to_path_buf()),
            temp_dir: root.join("tmp"),
            env,
        }
    }

    fn write_config(root: &Path, enable_ipv6: bool) {
        let config_dir = root.join("config");
        fs::create_dir_all(&config_dir).expect("mkdir config");
        fs::write(
            config_dir.join("config.toml"),
            format!("[ipset]\nset_name = \"kidobo\"\nenable_ipv6 = {enable_ipv6}\n"),
        )
        .expect("write config");
    }

    fn write_blocklist(root: &Path) {
        let data_dir = root.join("data");
        fs::create_dir_all(&data_dir).expect("mkdir data");
        fs::write(data_dir.join("blocklist.txt"), "# test\n").expect("write blocklist");
    }

    fn probe_ok() -> Result<CommandResult, CommandRunnerError> {
        Ok(CommandResult {
            status: Some(0),
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    fn find_check<'a>(checks: &'a [DoctorCheck], name: &str) -> &'a DoctorCheck {
        checks
            .iter()
            .find(|check| check.name == name)
            .expect("named check")
    }

    #[test]
    fn doctor_report_ok_and_skips_ipv6_checks_when_disabled() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write_config(root, false);
        write_blocklist(root);

        let locator = MockBinaryLocator::new(&[
            "sudo",
            "ipset",
            "iptables",
            "iptables-save",
            "iptables-restore",
        ]);
        let probes = MockProbeRunner::new(vec![probe_ok(), probe_ok(), probe_ok(), probe_ok()]);

        let report = build_doctor_report(&path_input_for_root(root), &locator, &probes);

        assert_eq!(report.overall, DoctorOverall::Ok);
        assert_eq!(
            find_check(&report.checks, "binary_ip6tables").status,
            DoctorCheckStatus::Skip
        );
        assert_eq!(
            find_check(&report.checks, "sudo_probe_ip6tables").status,
            DoctorCheckStatus::Skip
        );
        assert_eq!(probes.invocations().len(), 4);
    }

    #[test]
    fn doctor_report_fails_when_required_binary_is_missing() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write_config(root, true);
        write_blocklist(root);

        let locator = MockBinaryLocator::new(&[
            "sudo",
            "iptables",
            "iptables-save",
            "iptables-restore",
            "ip6tables",
        ]);
        let probes = MockProbeRunner::new(vec![probe_ok(), probe_ok(), probe_ok(), probe_ok()]);

        let report = build_doctor_report(&path_input_for_root(root), &locator, &probes);

        assert_eq!(report.overall, DoctorOverall::Fail);
        assert_eq!(
            find_check(&report.checks, "binary_ipset").status,
            DoctorCheckStatus::Fail
        );
        assert_eq!(
            find_check(&report.checks, "sudo_probe_ipset").status,
            DoctorCheckStatus::Skip
        );
    }

    #[test]
    fn doctor_report_fails_when_cache_is_not_writable() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write_config(root, false);
        write_blocklist(root);
        fs::create_dir_all(root.join("cache")).expect("mkdir cache root");
        fs::remove_dir_all(root.join("cache")).expect("remove cache root");
        fs::write(root.join("cache"), "not-a-directory").expect("write blocking file");

        let locator = MockBinaryLocator::new(&[
            "sudo",
            "ipset",
            "iptables",
            "iptables-save",
            "iptables-restore",
        ]);
        let probes = MockProbeRunner::new(vec![probe_ok(), probe_ok(), probe_ok(), probe_ok()]);

        let report = build_doctor_report(&path_input_for_root(root), &locator, &probes);

        assert_eq!(report.overall, DoctorOverall::Fail);
        assert_eq!(
            find_check(&report.checks, "cache_writable").status,
            DoctorCheckStatus::Fail
        );
    }

    #[test]
    fn doctor_report_fails_when_config_parse_fails() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fs::create_dir_all(root.join("config")).expect("mkdir config");
        fs::write(root.join("config/config.toml"), "not valid = [").expect("write config");
        write_blocklist(root);

        let locator = MockBinaryLocator::new(&[
            "sudo",
            "ipset",
            "iptables",
            "iptables-save",
            "iptables-restore",
        ]);
        let probes = MockProbeRunner::new(vec![probe_ok(), probe_ok(), probe_ok(), probe_ok()]);

        let report = build_doctor_report(&path_input_for_root(root), &locator, &probes);

        assert_eq!(report.overall, DoctorOverall::Fail);
        assert_eq!(
            find_check(&report.checks, "config_parse").status,
            DoctorCheckStatus::Fail
        );
        assert_eq!(
            find_check(&report.checks, "binary_ip6tables").status,
            DoctorCheckStatus::Skip
        );
        assert_eq!(
            find_check(&report.checks, "sudo_probe_ip6tables").status,
            DoctorCheckStatus::Skip
        );
    }
}
