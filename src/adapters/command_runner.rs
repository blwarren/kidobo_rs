use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub status: Option<i32>,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommandRunnerError {
    #[error("failed to spawn command `{command}`: {reason}")]
    Spawn { command: String, reason: String },

    #[error("failed to poll command `{command}`: {reason}")]
    Poll { command: String, reason: String },

    #[error("failed to read output for command `{command}`: {reason}")]
    Output { command: String, reason: String },

    #[error("command `{command}` timed out after {timeout_ms} ms")]
    Timeout { command: String, timeout_ms: u64 },
}

pub trait CommandExecutor {
    fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError> {
        let command = display_command(&request.program, &request.args);
        let mut child = Command::new(&request.program)
            .args(&request.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| CommandRunnerError::Spawn {
                command: command.clone(),
                reason: err.to_string(),
            })?;

        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    let output =
                        child
                            .wait_with_output()
                            .map_err(|err| CommandRunnerError::Output {
                                command: command.clone(),
                                reason: err.to_string(),
                            })?;

                    return Ok(CommandResult {
                        status: output.status.code(),
                        success: output.status.success(),
                        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    });
                }
                Ok(None) => {
                    if started.elapsed() >= request.timeout {
                        let _ = child.kill();
                        let _ = child.wait();

                        return Err(CommandRunnerError::Timeout {
                            command,
                            timeout_ms: duration_millis_u64(request.timeout),
                        });
                    }

                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();

                    return Err(CommandRunnerError::Poll {
                        command,
                        reason: err.to_string(),
                    });
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct SudoCommandRunner<E: CommandExecutor> {
    executor: E,
    default_timeout: Duration,
}

impl<E: CommandExecutor> SudoCommandRunner<E> {
    pub fn new(executor: E, default_timeout: Duration) -> Self {
        Self {
            executor,
            default_timeout,
        }
    }

    pub fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        self.run_with_timeout(command, args, self.default_timeout)
    }

    pub fn run_with_timeout(
        &self,
        command: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandResult, CommandRunnerError> {
        let mut sudo_args = Vec::with_capacity(args.len() + 2);
        sudo_args.push("-n".to_string());
        sudo_args.push(command.to_string());
        sudo_args.extend(args.iter().map(|value| (*value).to_string()));

        let request = CommandRequest {
            program: "sudo".to_string(),
            args: sudo_args,
            timeout,
        };

        self.executor.execute(&request)
    }
}

impl Default for SudoCommandRunner<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(SystemCommandExecutor, DEFAULT_COMMAND_TIMEOUT)
    }
}

fn display_command(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{} {}", program, args.join(" "))
    }
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::Duration;

    use super::{
        CommandExecutor, CommandRequest, CommandResult, CommandRunnerError, SudoCommandRunner,
    };

    struct MockExecutor {
        requests: RefCell<Vec<CommandRequest>>,
        responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
    }

    impl MockExecutor {
        fn new(responses: Vec<Result<CommandResult, CommandRunnerError>>) -> Self {
            Self {
                requests: RefCell::new(Vec::new()),
                responses: RefCell::new(VecDeque::from(responses)),
            }
        }

        fn requests(&self) -> Vec<CommandRequest> {
            self.requests.borrow().clone()
        }
    }

    impl CommandExecutor for MockExecutor {
        fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError> {
            self.requests.borrow_mut().push(request.clone());
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued response")
        }
    }

    #[test]
    fn wraps_commands_with_sudo_n_and_captures_output() {
        let executor = MockExecutor::new(vec![Ok(CommandResult {
            status: Some(0),
            success: true,
            stdout: "ok".to_string(),
            stderr: String::new(),
        })]);
        let runner = SudoCommandRunner::new(executor, Duration::from_secs(5));

        let result = runner
            .run("ipset", &["list", "kidobo"])
            .expect("command result");
        assert_eq!(result.status, Some(0));
        assert_eq!(result.stdout, "ok");
        assert_eq!(result.stderr, "");

        let requests = runner.executor.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].program, "sudo");
        assert_eq!(requests[0].args, vec!["-n", "ipset", "list", "kidobo"]);
        assert_eq!(requests[0].timeout, Duration::from_secs(5));
    }

    #[test]
    fn custom_timeout_overrides_default() {
        let executor = MockExecutor::new(vec![Ok(CommandResult {
            status: Some(0),
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        })]);
        let runner = SudoCommandRunner::new(executor, Duration::from_secs(30));

        let _ = runner
            .run_with_timeout("iptables", &["-S"], Duration::from_secs(2))
            .expect("command result");

        let requests = runner.executor.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].timeout, Duration::from_secs(2));
    }

    #[test]
    fn normalized_error_mapping_is_preserved() {
        let error = CommandRunnerError::Timeout {
            command: "sudo -n ipset list kidobo".to_string(),
            timeout_ms: 1_000,
        };

        let executor = MockExecutor::new(vec![Err(error.clone())]);
        let runner = SudoCommandRunner::new(executor, Duration::from_secs(1));

        let returned = runner
            .run("ipset", &["list", "kidobo"])
            .expect_err("must fail");
        assert_eq!(returned, error);
    }
}
