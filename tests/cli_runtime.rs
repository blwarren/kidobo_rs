use std::env;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use fs2::FileExt;
use kidobo::adapters::limited_io::read_to_string_with_limit;
use tempfile::TempDir;

const BLOCKLIST_READ_LIMIT: usize = 16 * 1024 * 1024;

fn run_kidobo(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kidobo"))
        .args(args)
        .output()
        .expect("run kidobo")
}

fn kidobo_with_root_command(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kidobo"));
    command
        .args(args)
        .env("KIDOBO_ROOT", root)
        .env("KIDOBO_ALLOW_REPO_CONFIG_FALLBACK", "0")
        .env_remove("KIDOBO_TEST_SANDBOX")
        .env_remove("KIDOBO_DISABLE_TEST_SANDBOX");
    command
}

fn run_kidobo_with_root(root: &Path, args: &[&str]) -> Output {
    kidobo_with_root_command(root, args)
        .output()
        .expect("run kidobo with root")
}

fn create_root(config_contents: &str, blocklist_contents: &str) -> TempDir {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();

    fs::create_dir_all(root.join("config")).expect("create config dir");
    fs::create_dir_all(root.join("data")).expect("create data dir");
    fs::create_dir_all(root.join("cache/remote")).expect("create remote cache dir");

    fs::write(root.join("config/config.toml"), config_contents).expect("write config");
    fs::write(root.join("data/blocklist.txt"), blocklist_contents).expect("write blocklist");

    temp
}

fn create_lookup_root(blocklist_contents: &str) -> TempDir {
    create_root("[ipset]\nset_name='kidobo'\n", blocklist_contents)
}

fn create_sync_root(config_contents: &str) -> TempDir {
    create_root(config_contents, "")
}

fn hold_lock(lock_path: &Path) -> std::fs::File {
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).expect("create lock parent");
    }

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .expect("open lock file");

    file.try_lock_exclusive().expect("hold lock");
    file
}

fn path_with_bin_prefix(bin_dir: &Path) -> String {
    match env::var("PATH") {
        Ok(path) if !path.is_empty() => format!("{}:{path}", bin_dir.display()),
        _ => bin_dir.display().to_string(),
    }
}

fn write_fake_sudo_script(temp: &TempDir) -> PathBuf {
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let script_path = bin_dir.join("sudo");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${KIDOBO_TEST_SUDO_TOUCHED:-}" ]]; then
  : > "${KIDOBO_TEST_SUDO_TOUCHED}"
fi

if [[ "${KIDOBO_TEST_SLEEP_ONCE:-0}" == "1" ]]; then
  marker="${KIDOBO_TEST_SLEEP_MARKER:-/tmp/kidobo-sudo-sleep.marker}"
  if [[ ! -f "${marker}" ]]; then
    : > "${marker}"
    sleep 2
  fi
fi

if [[ "${1:-}" != "-n" ]]; then
  echo "sudo: expected -n" >&2
  exit 1
fi

cmd="${2:-}"
shift 2

case "${cmd}" in
  ipset)
    case "${1:-}" in
      list|destroy)
        echo "The set with the given name does not exist" >&2
        exit 1
        ;;
      create|restore)
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  iptables|ip6tables)
    case "${1:-}" in
      -S)
        echo "No chain/target/match by that name" >&2
        exit 1
        ;;
      -D)
        echo "Bad rule (does a matching rule exist in that chain?)." >&2
        exit 1
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  *)
    exit 0
    ;;
esac
"#,
    )
    .expect("write fake sudo");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(&script_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).expect("chmod fake sudo");
    }

    script_path
}

#[test]
fn help_exits_with_zero() {
    let output = run_kidobo(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn version_exits_with_zero() {
    let output = run_kidobo(&["--version"]);
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "unexpected version output: {stdout}"
    );
}

#[test]
fn usage_error_exits_with_two() {
    let output = run_kidobo(&["lookup"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn lookup_uses_local_sources_and_exits_zero() {
    let root = create_lookup_root("203.0.113.7\n");
    let output = run_kidobo_with_root(root.path(), &["lookup", "203.0.113.7"]);

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("203.0.113.7\tinternal:blocklist\t203.0.113.7"),
        "unexpected lookup output: {stdout}"
    );
}

#[test]
fn lookup_file_mode_uses_local_sources_and_exits_zero() {
    let root = create_lookup_root("203.0.113.7\n");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "203.0.113.7\n").expect("write lookup targets");
    let target_path = targets.display().to_string();
    let args = vec!["lookup", "--file", target_path.as_str()];
    let output = run_kidobo_with_root(root.path(), &args);

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("203.0.113.7\tinternal:blocklist\t203.0.113.7"),
        "unexpected lookup output: {stdout}"
    );
}

#[test]
fn lookup_invalid_target_exits_with_one() {
    let root = create_lookup_root("203.0.113.7\n");
    let output = run_kidobo_with_root(root.path(), &["lookup", "not-an-ip"]);

    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid target: not-an-ip"),
        "missing invalid-target message: {stderr}"
    );
    assert!(
        stderr.contains("lookup failed for 1 invalid target(s)"),
        "missing final lookup error message: {stderr}"
    );
}

#[test]
fn sync_reports_config_parse_error_before_lock_check() {
    let root = create_sync_root("not valid = [");
    let _held_lock = hold_lock(&root.path().join("cache/sync.lock"));

    let output = run_kidobo_with_root(root.path(), &["sync"]);
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("config parse/validation failed"),
        "missing config parse failure in stderr: {stderr}"
    );
    assert!(
        !stderr.contains("lock already held"),
        "sync acquired lock before config parse: {stderr}"
    );
}

#[test]
fn sync_lock_held_fails_before_invoking_sudo() {
    let root = create_sync_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\ninclude_github_meta=false\n",
    );
    let _held_lock = hold_lock(&root.path().join("cache/sync.lock"));
    let fake_sudo = write_fake_sudo_script(&root);
    let touched = root.path().join("sudo-touched");

    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    command.env("KIDOBO_TEST_SUDO_TOUCHED", &touched);
    let output = command.output().expect("run sync with held lock");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lock already held"),
        "missing lock-held error message: {stderr}"
    );
    assert!(
        !touched.exists(),
        "side-effect command runner was invoked before lock failure"
    );
}

#[test]
fn sync_sigint_exits_with_130() {
    let root = create_sync_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\ninclude_github_meta=false\n",
    );
    let fake_sudo = write_fake_sudo_script(&root);
    let touched = root.path().join("sudo-touched");
    let sleep_marker = root.path().join("sudo-sleep-once.marker");

    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    command.env("KIDOBO_TEST_SUDO_TOUCHED", &touched);
    command.env("KIDOBO_TEST_SLEEP_ONCE", "1");
    command.env("KIDOBO_TEST_SLEEP_MARKER", &sleep_marker);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let child = command.spawn().expect("spawn sync");
    thread::sleep(Duration::from_millis(200));

    let signal_status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("send SIGINT");
    assert!(signal_status.success(), "failed to deliver SIGINT");

    let output = child.wait_with_output().expect("wait for sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(130),
        "expected SIGINT exit code 130, stderr:\n{stderr}"
    );
    assert!(
        touched.exists(),
        "test did not reach command execution before SIGINT"
    );
}

#[test]
fn sync_skips_local_blocklist_normalization_when_unchanged() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\ninclude_github_meta=false\n",
        "203.0.113.7\n203.0.113.0/24\n",
    );
    let fake_sudo = write_fake_sudo_script(&root);
    let sidecar = root.path().join("cache/blocklist-normalize.fast-state");
    let blocklist = root.path().join("data/blocklist.txt");
    let expected_canonical = "203.0.113.0/24\n";

    let mut first = kidobo_with_root_command(root.path(), &["sync"]);
    first.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    let first_output = first.output().expect("run first sync");
    assert_eq!(
        first_output.status.code(),
        Some(0),
        "first sync failed: {}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    assert!(
        sidecar.exists(),
        "fast-state sidecar was not created at {}",
        sidecar.display()
    );
    let first_blocklist = read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT)
        .expect("read canonicalized blocklist");
    assert_eq!(first_blocklist, expected_canonical);

    let mut second = kidobo_with_root_command(root.path(), &["sync"]);
    second.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    let second_output = second.output().expect("run second sync");
    assert_eq!(
        second_output.status.code(),
        Some(0),
        "second sync failed: {}",
        String::from_utf8_lossy(&second_output.stderr)
    );
    let second_stderr = String::from_utf8_lossy(&second_output.stderr);
    assert!(
        second_stderr.contains("sync blocklist normalization skipped: unchanged path="),
        "missing unchanged-blocklist skip log in second sync stderr: {second_stderr}"
    );

    let second_blocklist = read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT)
        .expect("read blocklist after second sync");
    assert_eq!(second_blocklist, expected_canonical);
}

#[test]
fn doctor_forced_human_color_emits_ansi_level_label() {
    let root = create_lookup_root("203.0.113.7\n");
    let mut command = kidobo_with_root_command(root.path(), &["doctor"]);
    command
        .env("KIDOBO_LOG_FORMAT", "human")
        .env("KIDOBO_LOG_COLOR", "always")
        .env_remove("NO_COLOR");
    let output = command.output().expect("run doctor with forced color");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("\u{1b}[32mINFO\u{1b}[0m: doctor report:"),
        "missing ANSI-colored INFO label in stderr (status {:?}): {stderr}",
        output.status.code()
    );
}
