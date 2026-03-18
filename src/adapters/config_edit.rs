use std::collections::BTreeSet;
use std::path::Path;

use toml::Value;

use crate::adapters::limited_io::{read_to_string_with_limit, write_string_atomic};
use crate::core::config::{ConfigError, DEFAULT_ASN_CACHE_STALE_AFTER_SECS};
use crate::error::KidoboError;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AsnBanUpdateResult {
    pub added: Vec<u32>,
    pub removed: Vec<u32>,
}

pub fn update_asn_bans(
    config_path: &Path,
    add: &[u32],
    remove: &[u32],
) -> Result<AsnBanUpdateResult, KidoboError> {
    let mut doc = load_config_value(config_path)?;
    let table = doc.as_table_mut().ok_or_else(|| KidoboError::ConfigParse {
        source: ConfigError::Parse {
            reason: "config root must be a TOML table".to_string(),
        },
    })?;
    let asn_value = table
        .entry("asn")
        .or_insert_with(|| Value::Table(toml::Table::new()));
    let asn_table = asn_value
        .as_table_mut()
        .ok_or_else(|| KidoboError::ConfigParse {
            source: ConfigError::InvalidField {
                field: "asn",
                reason: "must be a TOML table".to_string(),
            },
        })?;
    let existing = asn_table
        .get("banned")
        .map(parse_asn_list_from_toml)
        .transpose()?
        .unwrap_or_default();

    let mut before = BTreeSet::new();
    before.extend(existing);
    let mut after = before.clone();
    for asn in add {
        after.insert(*asn);
    }
    for asn in remove {
        after.remove(asn);
    }

    let added = after.difference(&before).copied().collect::<Vec<_>>();
    let removed = before.difference(&after).copied().collect::<Vec<_>>();
    let values = after
        .into_iter()
        .map(|asn| Value::Integer(i64::from(asn)))
        .collect::<Vec<_>>();
    asn_table.insert("banned".to_string(), Value::Array(values));
    if !asn_table.contains_key("cache_stale_after_secs") {
        asn_table.insert(
            "cache_stale_after_secs".to_string(),
            Value::Integer(i64::from(DEFAULT_ASN_CACHE_STALE_AFTER_SECS)),
        );
    }

    let rendered = toml::to_string_pretty(&doc).map_err(|err| KidoboError::ConfigParse {
        source: ConfigError::Parse {
            reason: err.to_string(),
        },
    })?;
    write_string_atomic(config_path, &rendered).map_err(|err| KidoboError::ConfigWrite {
        path: config_path.to_path_buf(),
        reason: err.to_string(),
    })?;
    Ok(AsnBanUpdateResult { added, removed })
}

fn load_config_value(path: &Path) -> Result<Value, KidoboError> {
    let contents =
        read_to_string_with_limit(path, 64 * 1024).map_err(|err| KidoboError::ConfigRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    toml::from_str::<Value>(&contents).map_err(|err| KidoboError::ConfigParse {
        source: ConfigError::Parse {
            reason: err.to_string(),
        },
    })
}

fn parse_asn_list_from_toml(value: &Value) -> Result<Vec<u32>, KidoboError> {
    let array = value.as_array().ok_or_else(|| KidoboError::ConfigParse {
        source: ConfigError::InvalidField {
            field: "asn.banned",
            reason: "must be an array".to_string(),
        },
    })?;
    let mut parsed = Vec::new();
    for raw in array {
        let Some(num) = raw.as_integer() else {
            return Err(KidoboError::ConfigParse {
                source: ConfigError::InvalidField {
                    field: "asn.banned",
                    reason: "must contain positive integers".to_string(),
                },
            });
        };
        if num <= 0 || num > i64::from(u32::MAX) {
            return Err(KidoboError::ConfigParse {
                source: ConfigError::InvalidField {
                    field: "asn.banned",
                    reason: "must contain positive integers".to_string(),
                },
            });
        }
        let parsed_asn = u32::try_from(num).map_err(|_| KidoboError::ConfigParse {
            source: ConfigError::InvalidField {
                field: "asn.banned",
                reason: "must contain positive integers".to_string(),
            },
        })?;
        parsed.push(parsed_asn);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::update_asn_bans;
    use crate::adapters::limited_io::read_to_string_with_limit;
    use crate::core::config::DEFAULT_ASN_CACHE_STALE_AFTER_SECS;
    use crate::error::KidoboError;

    #[test]
    fn update_asn_bans_adds_and_removes_values() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[64512]\n",
        )
        .expect("write");

        let added = update_asn_bans(&config_path, &[64513, 64514], &[]).expect("add");
        assert_eq!(added.added, vec![64513, 64514]);
        assert!(added.removed.is_empty());

        let removed = update_asn_bans(&config_path, &[], &[64512, 64514]).expect("remove");
        assert_eq!(removed.removed, vec![64512, 64514]);
    }

    #[test]
    fn update_asn_bans_creates_asn_table_when_missing() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(&config_path, "[ipset]\nset_name='kidobo'\n").expect("write");

        let result = update_asn_bans(&config_path, &[64513], &[]).expect("update");
        assert_eq!(result.added, vec![64513]);

        let rendered = read_to_string_with_limit(&config_path, 64 * 1024).expect("read");
        assert!(rendered.contains("[asn]"));
        assert!(rendered.contains("banned = [64513]"));
    }

    #[test]
    fn update_asn_bans_adds_default_cache_stale_after_when_missing() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[64512]\n",
        )
        .expect("write");

        let _ = update_asn_bans(&config_path, &[64513], &[]).expect("update");
        let rendered = read_to_string_with_limit(&config_path, 64 * 1024).expect("read");
        assert!(rendered.contains(&format!(
            "cache_stale_after_secs = {DEFAULT_ASN_CACHE_STALE_AFTER_SECS}"
        )));
    }

    #[test]
    fn update_asn_bans_rejects_non_array_banned_values() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[ipset]\nset_name='kidobo'\n[asn]\nbanned='not-an-array'\n",
        )
        .expect("write");

        let err = update_asn_bans(&config_path, &[64513], &[]).expect_err("must fail");
        assert!(matches!(
            err,
            KidoboError::ConfigParse {
                source: crate::core::config::ConfigError::InvalidField { field, .. }
            } if field == "asn.banned"
        ));
    }

    #[test]
    fn update_asn_bans_rejects_non_positive_asn_values() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[0]\n",
        )
        .expect("write");

        let err = update_asn_bans(&config_path, &[64513], &[]).expect_err("must fail");
        assert!(matches!(
            err,
            KidoboError::ConfigParse {
                source: crate::core::config::ConfigError::InvalidField { field, .. }
            } if field == "asn.banned"
        ));
    }
}
