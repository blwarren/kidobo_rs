use thiserror::Error;

use crate::adapters::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, SudoCommandRunner,
};

pub const KIDOBO_CHAIN_NAME: &str = "kidobo-input";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallFamily {
    Ipv4,
    Ipv6,
}

impl FirewallFamily {
    fn binary(self) -> &'static str {
        match self {
            Self::Ipv4 => "iptables",
            Self::Ipv6 => "ip6tables",
        }
    }
}

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("firewall command execution failed: {source}")]
    CommandExecution {
        #[from]
        source: CommandRunnerError,
    },

    #[error("firewall command failed `{command}` with status {status:?}: {stderr}")]
    CommandFailed {
        command: String,
        status: Option<i32>,
        stderr: String,
    },
}

pub trait FirewallCommandRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> FirewallCommandRunner for SudoCommandRunner<E> {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        SudoCommandRunner::run(self, command, args)
    }
}

pub fn chain_exists(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<bool, FirewallError> {
    let binary = family.binary();
    let result = runner.run(binary, &["-S", chain_name])?;
    if result.success {
        return Ok(true);
    }

    if is_missing_chain_result(&result) {
        return Ok(false);
    }

    Err(FirewallError::CommandFailed {
        command: format!("{binary} -S {chain_name}"),
        status: result.status,
        stderr: result.stderr,
    })
}

pub fn ensure_firewall_wiring(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    set_name: &str,
) -> Result<(), FirewallError> {
    ensure_chain_exists(runner, family, KIDOBO_CHAIN_NAME)?;
    remove_all_input_jumps_for_chain(runner, family, KIDOBO_CHAIN_NAME)?;
    insert_input_jump_at_top(runner, family, KIDOBO_CHAIN_NAME)?;
    enforce_chain_drop_rule(runner, family, KIDOBO_CHAIN_NAME, set_name)?;
    Ok(())
}

pub fn ensure_firewall_wiring_for_families(
    runner: &dyn FirewallCommandRunner,
    set_name_v4: &str,
    set_name_v6: &str,
    enable_ipv6: bool,
) -> Result<(), FirewallError> {
    ensure_firewall_wiring(runner, FirewallFamily::Ipv4, set_name_v4)?;

    if enable_ipv6 {
        ensure_firewall_wiring(runner, FirewallFamily::Ipv6, set_name_v6)?;
    }

    Ok(())
}

fn ensure_chain_exists(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<(), FirewallError> {
    if chain_exists(runner, family, chain_name)? {
        return Ok(());
    }

    run_checked(runner, family.binary(), &["-N", chain_name]).map(|_| ())
}

pub fn remove_all_input_jumps_for_chain(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<(), FirewallError> {
    let binary = family.binary();

    loop {
        let result = runner.run(binary, &["-D", "INPUT", "-j", chain_name])?;
        if result.success {
            continue;
        }

        if is_missing_rule_result(&result) {
            break;
        }

        return Err(FirewallError::CommandFailed {
            command: format!("{binary} -D INPUT -j {chain_name}"),
            status: result.status,
            stderr: result.stderr,
        });
    }

    Ok(())
}

fn insert_input_jump_at_top(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<(), FirewallError> {
    run_checked(
        runner,
        family.binary(),
        &["-I", "INPUT", "1", "-j", chain_name],
    )
    .map(|_| ())
}

fn enforce_chain_drop_rule(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
    set_name: &str,
) -> Result<(), FirewallError> {
    let binary = family.binary();
    run_checked(runner, binary, &["-F", chain_name])?;
    run_checked(
        runner,
        binary,
        &[
            "-A",
            chain_name,
            "-m",
            "set",
            "--match-set",
            set_name,
            "src",
            "-j",
            "DROP",
        ],
    )?;

    Ok(())
}

fn run_checked(
    runner: &dyn FirewallCommandRunner,
    command: &str,
    args: &[&str],
) -> Result<CommandResult, FirewallError> {
    let result = runner.run(command, args)?;
    if result.success {
        return Ok(result);
    }

    Err(FirewallError::CommandFailed {
        command: display_command(command, args),
        status: result.status,
        stderr: result.stderr,
    })
}

fn is_missing_chain_result(result: &CommandResult) -> bool {
    result.status == Some(1)
        && result
            .stderr
            .to_ascii_lowercase()
            .contains("no chain/target/match by that name")
}

fn is_missing_rule_result(result: &CommandResult) -> bool {
    result.status == Some(1) && result.stderr.to_ascii_lowercase().contains("bad rule")
}

fn display_command(command: &str, args: &[&str]) -> String {
    if args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, args.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::{
        FirewallCommandRunner, FirewallFamily, KIDOBO_CHAIN_NAME, chain_exists,
        ensure_firewall_wiring, ensure_firewall_wiring_for_families,
    };
    use crate::adapters::command_runner::{CommandResult, CommandRunnerError};

    struct MockRunner {
        responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
        invocations: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl MockRunner {
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

    impl FirewallCommandRunner for MockRunner {
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

    fn ok(status: i32) -> CommandResult {
        CommandResult {
            status: Some(status),
            success: status == 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn chain_exists_maps_missing_chain_to_false() {
        let runner = MockRunner::new(vec![Ok(CommandResult {
            status: Some(1),
            success: false,
            stdout: String::new(),
            stderr: "iptables: No chain/target/match by that name.".to_string(),
        })]);

        let exists =
            chain_exists(&runner, FirewallFamily::Ipv4, KIDOBO_CHAIN_NAME).expect("exists");
        assert!(!exists);
    }

    #[test]
    fn ensures_chain_jump_and_drop_rule_ordering() {
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "No chain/target/match by that name".to_string(),
            }),
            Ok(ok(0)), // -N chain
            Ok(CommandResult {
                status: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
            }),
            Ok(ok(0)), // -I INPUT 1 -j chain
            Ok(ok(0)), // -F chain
            Ok(ok(0)), // -A chain drop rule
        ]);

        ensure_firewall_wiring(&runner, FirewallFamily::Ipv4, "kidobo-set").expect("wiring");

        let invocations = runner.invocations();
        assert_eq!(invocations[0].0, "iptables");
        assert_eq!(invocations[0].1, vec!["-S", KIDOBO_CHAIN_NAME]);
        assert_eq!(invocations[1].1, vec!["-N", KIDOBO_CHAIN_NAME]);
        assert_eq!(
            invocations[2].1,
            vec!["-D", "INPUT", "-j", KIDOBO_CHAIN_NAME]
        );
        assert_eq!(
            invocations[3].1,
            vec!["-I", "INPUT", "1", "-j", KIDOBO_CHAIN_NAME]
        );
        assert_eq!(invocations[4].1, vec!["-F", KIDOBO_CHAIN_NAME]);
        assert_eq!(
            invocations[5].1,
            vec![
                "-A",
                KIDOBO_CHAIN_NAME,
                "-m",
                "set",
                "--match-set",
                "kidobo-set",
                "src",
                "-j",
                "DROP",
            ]
        );
    }

    #[test]
    fn removes_duplicate_input_jumps_before_reinserting() {
        let runner = MockRunner::new(vec![
            Ok(ok(0)), // -S chain exists
            Ok(ok(0)), // first -D INPUT -j chain
            Ok(ok(0)), // second -D INPUT -j chain
            Ok(CommandResult {
                status: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
            }),
            Ok(ok(0)), // -I
            Ok(ok(0)), // -F
            Ok(ok(0)), // -A
        ]);

        ensure_firewall_wiring(&runner, FirewallFamily::Ipv4, "kidobo-set").expect("wiring");

        let invocations = runner.invocations();
        assert_eq!(
            invocations[1].1,
            vec!["-D", "INPUT", "-j", KIDOBO_CHAIN_NAME]
        );
        assert_eq!(
            invocations[2].1,
            vec!["-D", "INPUT", "-j", KIDOBO_CHAIN_NAME]
        );
        assert_eq!(
            invocations[3].1,
            vec!["-D", "INPUT", "-j", KIDOBO_CHAIN_NAME]
        );
        assert_eq!(
            invocations[4].1,
            vec!["-I", "INPUT", "1", "-j", KIDOBO_CHAIN_NAME]
        );
    }

    #[test]
    fn supports_ipv6_parallel_wiring() {
        let runner = MockRunner::new(vec![
            Ok(ok(0)), // iptables -S
            Ok(CommandResult {
                status: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
            }),
            Ok(ok(0)),
            Ok(ok(0)),
            Ok(ok(0)),
            Ok(ok(0)), // ip6tables -S
            Ok(CommandResult {
                status: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
            }),
            Ok(ok(0)),
            Ok(ok(0)),
            Ok(ok(0)),
        ]);

        ensure_firewall_wiring_for_families(&runner, "kidobo-v4", "kidobo-v6", true)
            .expect("wiring");

        let invocations = runner.invocations();
        assert_eq!(invocations[0].0, "iptables");
        assert_eq!(invocations[5].0, "ip6tables");
    }
}
