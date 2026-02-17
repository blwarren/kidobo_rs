use std::fs;
use std::path::PathBuf;

use crate::adapters::config::load_config_from_file;
use crate::adapters::lookup_sources::load_lookup_sources;
use crate::adapters::path::{PathResolutionInput, resolve_paths};
use crate::cli::args::Command;
use crate::cli::blocklist::{run_ban_command, run_unban_command};
use crate::cli::doctor::run_doctor_command;
use crate::cli::flush::run_flush_command;
use crate::cli::init::run_init_command;
use crate::cli::sync::run_sync_command;
use crate::core::lookup::run_lookup;
use crate::error::KidoboError;

pub fn dispatch(command: Command) -> Result<(), KidoboError> {
    match command {
        Command::Init => run_init_command(),
        Command::Doctor => run_doctor_command(),
        Command::Sync => run_sync_command(),
        Command::Flush { cache_only } => run_flush_command(cache_only),
        Command::Lookup { ip, file } => run_lookup_command(ip, file),
        Command::Ban { target } => run_ban_command(&target),
        Command::Unban { target, yes } => run_unban_command(&target, yes),
    }
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn run_lookup_command(ip: Option<String>, file: Option<PathBuf>) -> Result<(), KidoboError> {
    let targets = collect_lookup_targets(ip, file)?;

    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;

    let _config = load_config_from_file(&paths.config_file)?;
    let sources = load_lookup_sources(&paths)?;

    let report = run_lookup(&targets, &sources);

    for matched in &report.matches {
        println!(
            "{}\t{}\t{}",
            matched.target, matched.source_label, matched.matched_source_entry
        );
    }

    for invalid in &report.invalid_targets {
        eprintln!("invalid target: {invalid}");
    }

    if !report.invalid_targets.is_empty() {
        return Err(KidoboError::LookupInvalidTargets {
            count: report.invalid_targets.len(),
        });
    }

    Ok(())
}

fn collect_lookup_targets(
    ip: Option<String>,
    file: Option<PathBuf>,
) -> Result<Vec<String>, KidoboError> {
    match (ip, file) {
        (Some(target), None) => Ok(vec![target]),
        (None, Some(path)) => read_target_lines(&path),
        _ => Ok(Vec::new()),
    }
}

fn read_target_lines(path: &std::path::Path) -> Result<Vec<String>, KidoboError> {
    let contents = fs::read_to_string(path).map_err(|err| KidoboError::LookupTargetFileRead {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;

    Ok(contents.lines().map(ToString::to_string).collect())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::{collect_lookup_targets, read_target_lines};
    use crate::error::KidoboError;

    #[test]
    fn lookup_target_collection_single_mode() {
        let targets =
            collect_lookup_targets(Some("203.0.113.7".to_string()), None).expect("collect");
        assert_eq!(targets, vec!["203.0.113.7"]);
    }

    #[test]
    fn lookup_target_collection_file_mode() {
        let temp = TempDir::new().expect("tempdir");
        let file = temp.path().join("targets.txt");
        fs::write(&file, "10.0.0.1\n2001:db8::1\n").expect("write");

        let targets = collect_lookup_targets(None, Some(file)).expect("collect");
        assert_eq!(targets, vec!["10.0.0.1", "2001:db8::1"]);
    }

    #[test]
    fn read_target_lines_reports_file_read_error() {
        let missing = PathBuf::from("/definitely/missing/targets.txt");
        let err = read_target_lines(&missing).expect_err("must fail");
        match err {
            KidoboError::LookupTargetFileRead { path, .. } => assert_eq!(path, missing),
            _ => panic!("unexpected error variant"),
        }
    }
}
