use crate::adapters::command_runner::{CommandResult, ProcessStatus};

pub fn display_command<S: AsRef<str>>(command: &str, args: &[S]) -> String {
    if args.is_empty() {
        command.to_string()
    } else {
        let rendered_args = args.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ");
        format!("{command} {rendered_args}")
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
        assert_eq!(display_command("ipset", &[] as &[&str]), "ipset");
        assert_eq!(
            display_command("iptables", &["-A", "INPUT", "-j", "DROP"]),
            "iptables -A INPUT -j DROP"
        );
        assert_eq!(
            display_command(
                "sudo",
                &[
                    "ipset".to_string(),
                    "list".to_string(),
                    "kidobo".to_string()
                ]
            ),
            "sudo ipset list kidobo"
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
