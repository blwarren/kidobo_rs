use std::path::PathBuf;

use crate::adapters::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, SudoCommandRunner,
};
use crate::error::KidoboError;

use super::templates::{KIDOBO_SYNC_SERVICE_FILE, KIDOBO_SYNC_TIMER_FILE};

pub(super) const DEFAULT_KIDOBO_BINARY_PATH: &str = "/usr/local/bin/kidobo";
pub(super) const FALLBACK_KIDOBO_BINARY_PATH: &str = "/usr/bin/kidobo";

pub(super) trait InitCommandRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> InitCommandRunner for SudoCommandRunner<E> {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        SudoCommandRunner::run(self, command, args)
    }
}

#[cfg(test)]
pub(super) struct NoopInitCommandRunner;

#[cfg(test)]
impl InitCommandRunner for NoopInitCommandRunner {
    fn run(&self, _command: &str, _args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        Ok(CommandResult {
            status: crate::adapters::command_runner::ProcessStatus::Exited(0),
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

pub(super) fn resolve_installed_executable_path(
    candidates: &[PathBuf],
) -> Result<PathBuf, KidoboError> {
    candidates
        .iter()
        .find(|candidate| candidate.is_file())
        .cloned()
        .ok_or_else(|| KidoboError::InitBinaryPathUnavailable {
            candidates: candidates
                .iter()
                .map(|candidate| candidate.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        })
}

pub(super) fn ensure_systemd_timer_enabled(
    runner: &dyn InitCommandRunner,
) -> Result<(), KidoboError> {
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

    if result.status.success() {
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
