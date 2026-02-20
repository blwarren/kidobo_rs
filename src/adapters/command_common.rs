use crate::adapters::command_runner::{CommandResult, ProcessStatus};

pub fn display_command(command: &str, args: &[&str]) -> String {
    if args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, args.join(" "))
    }
}

pub fn ensure_command_succeeded<E, F>(
    result: CommandResult,
    command: &str,
    args: &[&str],
    build_error: F,
) -> Result<CommandResult, E>
where
    F: FnOnce(String, ProcessStatus, String) -> E,
{
    if result.status.success() {
        return Ok(result);
    }

    Err(build_error(
        display_command(command, args),
        result.status,
        result.stderr,
    ))
}

#[cfg(test)]
mod tests {
    use super::{display_command, ensure_command_succeeded};
    use crate::adapters::command_runner::CommandResult;

    #[test]
    fn display_command_renders_command_and_args() {
        assert_eq!(display_command("ipset", &[]), "ipset");
        assert_eq!(
            display_command("iptables", &["-A", "INPUT", "-j", "DROP"]),
            "iptables -A INPUT -j DROP"
        );
    }

    #[test]
    fn ensure_command_succeeded_passes_success_through() {
        let result = CommandResult {
            status: crate::adapters::command_runner::ProcessStatus::Exited(0),
            stdout: "ok".to_string(),
            stderr: String::new(),
        };
        let output = ensure_command_succeeded(result, "ipset", &["list"], |_, _, _| ())
            .expect("success should pass through");
        assert_eq!(output.stdout, "ok");
    }
}
