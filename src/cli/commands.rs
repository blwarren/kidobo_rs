use crate::cli::args::Command;
use crate::error::KidoboError;

pub fn dispatch(command: Command) -> Result<(), KidoboError> {
    match command {
        Command::Init => Err(KidoboError::UnimplementedCommand { command: "init" }),
        Command::Doctor => Err(KidoboError::UnimplementedCommand { command: "doctor" }),
        Command::Sync => Err(KidoboError::UnimplementedCommand { command: "sync" }),
        Command::Flush => Err(KidoboError::UnimplementedCommand { command: "flush" }),
        Command::Lookup { ip, file } => {
            let _ = (ip, file);
            Err(KidoboError::UnimplementedCommand { command: "lookup" })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::dispatch;
    use crate::cli::args::Command;
    use crate::error::KidoboError;

    #[test]
    fn all_commands_are_routed() {
        let cases = vec![
            (Command::Init, "init"),
            (Command::Doctor, "doctor"),
            (Command::Sync, "sync"),
            (Command::Flush, "flush"),
            (
                Command::Lookup {
                    ip: Some("127.0.0.1".to_string()),
                    file: None,
                },
                "lookup",
            ),
            (
                Command::Lookup {
                    ip: None,
                    file: Some(PathBuf::from("targets.txt")),
                },
                "lookup",
            ),
        ];

        for (command, expected) in cases {
            let err = dispatch(command).expect_err("commands are currently stubs");
            match err {
                KidoboError::UnimplementedCommand { command } => assert_eq!(command, expected),
                _ => panic!("unexpected error variant"),
            }
        }
    }
}
