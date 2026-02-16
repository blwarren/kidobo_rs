use serde::Deserialize;
use thiserror::Error;

pub const DEFAULT_IPSET_TYPE: &str = "hash:net";
pub const DEFAULT_HASHSIZE: u32 = 65_536;
pub const DEFAULT_MAXELEM: u32 = 500_000;
pub const DEFAULT_TIMEOUT: u32 = 0;
pub const DEFAULT_REMOTE_TIMEOUT_SECS: u32 = 30;
pub const DEFAULT_INCLUDE_GITHUB_META: bool = true;
pub const DEFAULT_GITHUB_META_CATEGORIES: [&str; 4] = ["api", "git", "hooks", "packages"];
pub const DEFAULT_GITHUB_META_URL: &str = "https://api.github.com/meta";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub ipset: IpsetConfig,
    pub safe: SafeConfig,
    pub remote: RemoteConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsetConfig {
    pub set_name: String,
    pub set_name_v6: String,
    pub enable_ipv6: bool,
    pub set_type: String,
    pub hashsize: u32,
    pub maxelem: u32,
    pub timeout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeConfig {
    pub ips: Vec<String>,
    pub include_github_meta: bool,
    pub github_meta_url: String,
    pub github_meta_categories: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConfig {
    pub urls: Vec<String>,
    pub timeout_secs: u32,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            timeout_secs: DEFAULT_REMOTE_TIMEOUT_SECS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubMetaCategoryMode {
    Default,
    All,
    Explicit(Vec<String>),
}

impl SafeConfig {
    pub fn github_meta_category_mode(&self) -> GithubMetaCategoryMode {
        match &self.github_meta_categories {
            None => GithubMetaCategoryMode::Default,
            Some(values) if values.is_empty() => GithubMetaCategoryMode::All,
            Some(values) => GithubMetaCategoryMode::Explicit(values.clone()),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("failed to parse TOML config: {reason}")]
    Parse { reason: String },

    #[error("missing required config section `[ipset]`")]
    MissingIpsetSection,

    #[error("invalid config value for `{field}`: {reason}")]
    InvalidField { field: &'static str, reason: String },
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    ipset: Option<RawIpsetConfig>,
    safe: Option<RawSafeConfig>,
    remote: Option<RawRemoteConfig>,
}

#[derive(Debug, Deserialize)]
struct RawIpsetConfig {
    set_name: Option<String>,
    set_name_v6: Option<String>,
    enable_ipv6: Option<bool>,
    set_type: Option<String>,
    hashsize: Option<i64>,
    maxelem: Option<i64>,
    timeout: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
struct RawSafeConfig {
    ips: Option<Vec<String>>,
    include_github_meta: Option<bool>,
    github_meta_url: Option<String>,
    github_meta_categories: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct RawRemoteConfig {
    urls: Option<Vec<String>>,
    timeout_secs: Option<i64>,
}

impl Config {
    pub fn from_toml_str(contents: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(contents).map_err(|err| ConfigError::Parse {
            reason: err.to_string(),
        })?;

        Self::from_raw(raw)
    }

    fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        let raw_ipset = raw.ipset.ok_or(ConfigError::MissingIpsetSection)?;
        let ipset = parse_ipset(raw_ipset)?;
        let safe = parse_safe(raw.safe.unwrap_or_default())?;
        let remote = parse_remote(raw.remote.unwrap_or_default())?;

        Ok(Self {
            ipset,
            safe,
            remote,
        })
    }
}

fn parse_ipset(raw: RawIpsetConfig) -> Result<IpsetConfig, ConfigError> {
    let set_name = required_non_empty(raw.set_name, "ipset.set_name")?;
    validate_ipset_set_name(&set_name, "ipset.set_name")?;

    let set_name_v6 = match raw.set_name_v6 {
        Some(value) => {
            let parsed = non_empty(value, "ipset.set_name_v6")?;
            validate_ipset_set_name(&parsed, "ipset.set_name_v6")?;
            parsed
        }
        None => {
            let derived = format!("{set_name}-v6");
            validate_ipset_set_name(&derived, "ipset.set_name_v6")?;
            derived
        }
    };

    let enable_ipv6 = raw.enable_ipv6.unwrap_or(true);
    let set_type = match raw.set_type {
        Some(value) => {
            let parsed = non_empty(value, "ipset.set_type")?;
            validate_ipset_set_type(&parsed)?;
            parsed
        }
        None => DEFAULT_IPSET_TYPE.to_string(),
    };

    let hashsize = bounded_u32(
        raw.hashsize.unwrap_or(i64::from(DEFAULT_HASHSIZE)),
        "ipset.hashsize",
        1,
        u32::MAX,
    )?;
    if !hashsize.is_power_of_two() {
        return Err(ConfigError::InvalidField {
            field: "ipset.hashsize",
            reason: "must be a power-of-two positive integer".to_string(),
        });
    }

    let maxelem = bounded_u32(
        raw.maxelem.unwrap_or(i64::from(DEFAULT_MAXELEM)),
        "ipset.maxelem",
        1,
        DEFAULT_MAXELEM,
    )?;

    let timeout = bounded_u32(
        raw.timeout.unwrap_or(i64::from(DEFAULT_TIMEOUT)),
        "ipset.timeout",
        0,
        u32::MAX,
    )?;

    Ok(IpsetConfig {
        set_name,
        set_name_v6,
        enable_ipv6,
        set_type,
        hashsize,
        maxelem,
        timeout,
    })
}

fn parse_safe(raw: RawSafeConfig) -> Result<SafeConfig, ConfigError> {
    let mut ips = Vec::new();
    if let Some(values) = raw.ips {
        for value in values {
            ips.push(non_empty(value, "safe.ips")?);
        }
    }

    let include_github_meta = raw
        .include_github_meta
        .unwrap_or(DEFAULT_INCLUDE_GITHUB_META);

    let github_meta_url = match raw.github_meta_url {
        Some(value) => {
            let parsed = non_empty(value, "safe.github_meta_url")?;
            validate_http_url(&parsed, "safe.github_meta_url")?;
            parsed
        }
        None => DEFAULT_GITHUB_META_URL.to_string(),
    };

    let github_meta_categories = match raw.github_meta_categories {
        None => None,
        Some(values) => {
            let mut normalized = Vec::with_capacity(values.len());
            for value in values {
                normalized.push(non_empty(value, "safe.github_meta_categories")?);
            }
            Some(normalized)
        }
    };

    Ok(SafeConfig {
        ips,
        include_github_meta,
        github_meta_url,
        github_meta_categories,
    })
}

fn parse_remote(raw: RawRemoteConfig) -> Result<RemoteConfig, ConfigError> {
    let mut urls = Vec::new();
    if let Some(values) = raw.urls {
        for value in values {
            urls.push(non_empty(value, "remote.urls")?);
        }
    }

    let timeout_secs = bounded_u32(
        raw.timeout_secs
            .unwrap_or(i64::from(DEFAULT_REMOTE_TIMEOUT_SECS)),
        "remote.timeout_secs",
        1,
        3600,
    )?;

    Ok(RemoteConfig { urls, timeout_secs })
}

fn required_non_empty(value: Option<String>, field: &'static str) -> Result<String, ConfigError> {
    match value {
        Some(value) => non_empty(value, field),
        None => Err(ConfigError::InvalidField {
            field,
            reason: "value is required".to_string(),
        }),
    }
}

fn non_empty(value: String, field: &'static str) -> Result<String, ConfigError> {
    let normalized = value.trim().to_string();
    if normalized.is_empty() {
        return Err(ConfigError::InvalidField {
            field,
            reason: "value must not be empty".to_string(),
        });
    }

    Ok(normalized)
}

fn bounded_u32(value: i64, field: &'static str, min: u32, max: u32) -> Result<u32, ConfigError> {
    if value < i64::from(min) || value > i64::from(max) {
        return Err(ConfigError::InvalidField {
            field,
            reason: format!("must be between {min} and {max}"),
        });
    }

    Ok(value as u32)
}

fn validate_ipset_set_name(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.len() > 31 {
        return Err(ConfigError::InvalidField {
            field,
            reason: "must be 31 characters or fewer".to_string(),
        });
    }

    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ConfigError::InvalidField {
            field,
            reason: "must contain only [A-Za-z0-9_.-]".to_string(),
        });
    }

    Ok(())
}

fn validate_ipset_set_type(value: &str) -> Result<(), ConfigError> {
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b':' | b',' | b'_' | b'-' | b'.')
    }) {
        return Err(ConfigError::InvalidField {
            field: "ipset.set_type",
            reason: "must contain only [A-Za-z0-9:,_-.]".to_string(),
        });
    }

    Ok(())
}

fn validate_http_url(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.starts_with("http://") || value.starts_with("https://") {
        Ok(())
    } else {
        Err(ConfigError::InvalidField {
            field,
            reason: "must start with http:// or https://".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Config, ConfigError, DEFAULT_GITHUB_META_CATEGORIES, DEFAULT_GITHUB_META_URL,
        DEFAULT_HASHSIZE, DEFAULT_IPSET_TYPE, DEFAULT_MAXELEM, DEFAULT_REMOTE_TIMEOUT_SECS,
        DEFAULT_TIMEOUT, GithubMetaCategoryMode,
    };

    #[test]
    fn parses_minimal_config_and_applies_defaults() {
        let config = Config::from_toml_str("[ipset]\nset_name = 'kidobo'\n").expect("parse");

        assert_eq!(config.ipset.set_name, "kidobo");
        assert_eq!(config.ipset.set_name_v6, "kidobo-v6");
        assert!(config.ipset.enable_ipv6);
        assert_eq!(config.ipset.set_type, DEFAULT_IPSET_TYPE);
        assert_eq!(config.ipset.hashsize, DEFAULT_HASHSIZE);
        assert_eq!(config.ipset.maxelem, DEFAULT_MAXELEM);
        assert_eq!(config.ipset.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.safe.ips, Vec::<String>::new());
        assert!(config.safe.include_github_meta);
        assert_eq!(config.safe.github_meta_url, DEFAULT_GITHUB_META_URL);
        assert_eq!(
            config.safe.github_meta_category_mode(),
            GithubMetaCategoryMode::Default
        );
        assert_eq!(
            DEFAULT_GITHUB_META_CATEGORIES,
            ["api", "git", "hooks", "packages"]
        );
        assert_eq!(config.remote.urls, Vec::<String>::new());
        assert_eq!(config.remote.timeout_secs, DEFAULT_REMOTE_TIMEOUT_SECS);
    }

    #[test]
    fn set_name_v6_can_be_overridden() {
        let config =
            Config::from_toml_str("[ipset]\nset_name = 'kidobo'\nset_name_v6 = 'custom-v6'\n")
                .expect("parse");

        assert_eq!(config.ipset.set_name_v6, "custom-v6");
    }

    #[test]
    fn enable_ipv6_false_is_respected() {
        let config = Config::from_toml_str("[ipset]\nset_name='kidobo'\nenable_ipv6=false\n")
            .expect("parse");

        assert!(!config.ipset.enable_ipv6);
    }

    #[test]
    fn safe_empty_categories_means_all() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[safe]\ngithub_meta_categories=[]\n",
        )
        .expect("parse");

        assert_eq!(
            config.safe.github_meta_category_mode(),
            GithubMetaCategoryMode::All
        );
    }

    #[test]
    fn safe_explicit_categories_are_preserved() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[safe]\ngithub_meta_categories=['api','hooks']\n",
        )
        .expect("parse");

        assert_eq!(
            config.safe.github_meta_category_mode(),
            GithubMetaCategoryMode::Explicit(vec!["api".to_string(), "hooks".to_string()])
        );
    }

    #[test]
    fn safe_github_meta_url_can_be_overridden() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[safe]\ngithub_meta_url='https://example.com/meta'\n",
        )
        .expect("parse");
        assert_eq!(config.safe.github_meta_url, "https://example.com/meta");
    }

    #[test]
    fn safe_github_meta_url_must_be_http_or_https() {
        let err = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[safe]\ngithub_meta_url='ftp://example.com/meta'\n",
        )
        .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "safe.github_meta_url",
                reason: "must start with http:// or https://".to_string(),
            }
        );
    }

    #[test]
    fn missing_ipset_section_fails() {
        let err = Config::from_toml_str("[safe]\nips=[]\n").expect_err("must fail");
        assert_eq!(err, ConfigError::MissingIpsetSection);
    }

    #[test]
    fn missing_set_name_fails() {
        let err = Config::from_toml_str("[ipset]\n").expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_name",
                reason: "value is required".to_string(),
            }
        );
    }

    #[test]
    fn hashsize_must_be_power_of_two() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\nhashsize=100\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.hashsize",
                reason: "must be a power-of-two positive integer".to_string(),
            }
        );
    }

    #[test]
    fn maxelem_must_be_in_allowed_range() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\nmaxelem=500001\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.maxelem",
                reason: "must be between 1 and 500000".to_string(),
            }
        );
    }

    #[test]
    fn timeout_must_be_non_negative() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\ntimeout=-1\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.timeout",
                reason: format!("must be between {} and {}", 0, u32::MAX),
            }
        );
    }

    #[test]
    fn set_name_rejects_whitespace_and_overlength_values() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo bad'\n").expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_name",
                reason: "must contain only [A-Za-z0-9_.-]".to_string(),
            }
        );

        let err =
            Config::from_toml_str("[ipset]\nset_name='kidobo-name-that-is-way-too-long-12345'\n")
                .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_name",
                reason: "must be 31 characters or fewer".to_string(),
            }
        );
    }

    #[test]
    fn set_type_rejects_whitespace_and_control_characters() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\nset_type='hash: net'\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_type",
                reason: "must contain only [A-Za-z0-9:,_-.]".to_string(),
            }
        );

        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\nset_type='hash:net\\nadd'\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_type",
                reason: "must contain only [A-Za-z0-9:,_-.]".to_string(),
            }
        );
    }

    #[test]
    fn empty_remote_url_fails() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\n[remote]\nurls=['']\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "remote.urls",
                reason: "value must not be empty".to_string(),
            }
        );
    }

    #[test]
    fn remote_timeout_secs_can_be_overridden() {
        let config =
            Config::from_toml_str("[ipset]\nset_name='kidobo'\n[remote]\ntimeout_secs=45\n")
                .expect("parse");
        assert_eq!(config.remote.timeout_secs, 45);
    }

    #[test]
    fn remote_timeout_secs_must_be_within_allowed_range() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\n[remote]\ntimeout_secs=0\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "remote.timeout_secs",
                reason: "must be between 1 and 3600".to_string(),
            }
        );

        let err =
            Config::from_toml_str("[ipset]\nset_name='kidobo'\n[remote]\ntimeout_secs=3601\n")
                .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "remote.timeout_secs",
                reason: "must be between 1 and 3600".to_string(),
            }
        );
    }

    #[test]
    fn parse_errors_are_mapped() {
        let err = Config::from_toml_str("not toml").expect_err("must fail");
        match err {
            ConfigError::Parse { .. } => {}
            _ => panic!("expected parse error"),
        }
    }
}
