use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn run_kidobo(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kidobo"))
        .args(args)
        .output()
        .expect("run kidobo")
}

fn run_kidobo_with_root(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kidobo"))
        .args(args)
        .env("KIDOBO_ROOT", root)
        .env("KIDOBO_ALLOW_REPO_CONFIG_FALLBACK", "0")
        .env_remove("KIDOBO_TEST_SANDBOX")
        .env_remove("KIDOBO_DISABLE_TEST_SANDBOX")
        .output()
        .expect("run kidobo with root")
}

fn create_lookup_root(blocklist_contents: &str) -> TempDir {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();

    fs::create_dir_all(root.join("config")).expect("create config dir");
    fs::create_dir_all(root.join("data")).expect("create data dir");
    fs::create_dir_all(root.join("cache/remote")).expect("create remote cache dir");

    fs::write(
        root.join("config/config.toml"),
        "[ipset]\nset_name='kidobo'\n",
    )
    .expect("write config");
    fs::write(root.join("data/blocklist.txt"), blocklist_contents).expect("write blocklist");

    temp
}

#[test]
fn help_exits_with_zero() {
    let output = run_kidobo(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
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
