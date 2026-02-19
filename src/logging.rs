use std::env;
use std::io::{IsTerminal, Write};

use env_logger::WriteStyle;
use log::LevelFilter;

use crate::error::KidoboError;

pub fn init(level: LevelFilter) -> Result<(), KidoboError> {
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level);
    builder.write_style(WriteStyle::Never);
    let format = select_log_format(
        env::var_os("KIDOBO_LOG_FORMAT").as_deref(),
        std::io::stderr().is_terminal(),
        running_under_systemd(),
    );
    builder.format(move |buf, record| match format {
        LogFormat::Human => writeln!(buf, "{}: {}", record.level(), record.args()),
        LogFormat::Journal => writeln!(buf, "level={} msg={}", record.level(), record.args()),
    });
    builder.try_init().map_err(|err| KidoboError::LoggerInit {
        reason: err.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Human,
    Journal,
}

fn running_under_systemd() -> bool {
    env::var_os("INVOCATION_ID").is_some() || env::var_os("JOURNAL_STREAM").is_some()
}

fn select_log_format(
    configured: Option<&std::ffi::OsStr>,
    stderr_is_terminal: bool,
    under_systemd: bool,
) -> LogFormat {
    match configured
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) if value.eq_ignore_ascii_case("human") => LogFormat::Human,
        Some(value) if value.eq_ignore_ascii_case("journal") => LogFormat::Journal,
        Some(value) if value.eq_ignore_ascii_case("auto") => {
            auto_log_format(stderr_is_terminal, under_systemd)
        }
        Some(_) | None => auto_log_format(stderr_is_terminal, under_systemd),
    }
}

fn auto_log_format(stderr_is_terminal: bool, under_systemd: bool) -> LogFormat {
    if under_systemd || !stderr_is_terminal {
        LogFormat::Journal
    } else {
        LogFormat::Human
    }
}

#[cfg(test)]
mod tests {
    use log::LevelFilter;

    use super::{LogFormat, auto_log_format, init, select_log_format};
    use crate::error::KidoboError;

    #[test]
    fn repeated_init_reports_logger_init_error() {
        let _ = init(LevelFilter::Off);

        let err = init(LevelFilter::Off).expect_err("second init must fail");
        match err {
            KidoboError::LoggerInit { reason } => assert!(!reason.is_empty()),
            _ => panic!("expected logger init error"),
        }
    }

    #[test]
    fn auto_format_prefers_journal_for_non_tty_or_systemd() {
        assert_eq!(auto_log_format(false, false), LogFormat::Journal);
        assert_eq!(auto_log_format(true, true), LogFormat::Journal);
    }

    #[test]
    fn auto_format_uses_human_for_interactive_non_systemd() {
        assert_eq!(auto_log_format(true, false), LogFormat::Human);
    }

    #[test]
    fn explicit_format_overrides_auto_detection() {
        assert_eq!(
            select_log_format(Some("human".as_ref()), false, true),
            LogFormat::Human
        );
        assert_eq!(
            select_log_format(Some("journal".as_ref()), true, false),
            LogFormat::Journal
        );
    }

    #[test]
    fn invalid_or_missing_config_falls_back_to_auto() {
        assert_eq!(select_log_format(None, true, false), LogFormat::Human);
        assert_eq!(
            select_log_format(Some("unknown".as_ref()), true, true),
            LogFormat::Journal
        );
    }
}
