use std::path::Path;

use crate::adapters::limited_io::read_to_string_with_limit;
use crate::core::config::Config;
use crate::error::KidoboError;

const CONFIG_READ_LIMIT: usize = 64 * 1024;

pub fn load_config_from_file(path: &Path) -> Result<Config, KidoboError> {
    if !path.exists() {
        return Err(KidoboError::MissingConfigFile {
            path: path.to_path_buf(),
        });
    }

    let contents = read_to_string_with_limit(path, CONFIG_READ_LIMIT).map_err(|err| {
        KidoboError::ConfigRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    Config::from_toml_str(&contents).map_err(KidoboError::from)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::load_config_from_file;
    use crate::error::KidoboError;

    #[test]
    fn missing_config_file_fails() {
        let temp = TempDir::new().expect("tempdir");
        let missing = temp.path().join("missing.toml");

        let err = load_config_from_file(&missing).expect_err("must fail");
        assert_eq!(
            err.to_string(),
            format!("config file does not exist: {}", missing.display())
        );
    }

    #[test]
    fn reads_and_parses_config() {
        let temp = TempDir::new().expect("tempdir");
        let config_file = temp.path().join("config.toml");
        fs::write(&config_file, "[ipset]\nset_name='kidobo'\n").expect("write");

        let config = load_config_from_file(&config_file).expect("load");
        assert_eq!(config.ipset.set_name, "kidobo");
    }

    #[test]
    fn parse_error_is_returned() {
        let temp = TempDir::new().expect("tempdir");
        let config_file = temp.path().join("config.toml");
        fs::write(&config_file, "not toml").expect("write");

        let err = load_config_from_file(&config_file).expect_err("must fail");
        match err {
            KidoboError::ConfigParse { .. } => {}
            _ => panic!("expected config parse error"),
        }
    }
}
