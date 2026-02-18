use std::sync::Arc;

use crate::core::network::{
    CanonicalCidr, IntervalU32, IntervalU128, cidr_overlaps as network_cidr_overlaps,
    ipv4_to_interval, ipv6_to_interval, parse_ip_cidr_token,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupSourceEntry {
    pub source_label: Arc<str>,
    pub source_line: String,
    pub cidr: CanonicalCidr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupMatch {
    pub target: String,
    pub source_label: String,
    pub matched_source_entry: String,
    pub matched_cidr: CanonicalCidr,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LookupReport {
    pub matches: Vec<LookupMatch>,
    pub invalid_targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupTargetParseError {
    Empty,
    Invalid,
}

pub fn parse_target_strict(input: &str) -> Result<CanonicalCidr, LookupTargetParseError> {
    let normalized = input.trim();
    if normalized.is_empty() {
        return Err(LookupTargetParseError::Empty);
    }

    if normalized.split_whitespace().count() != 1 {
        return Err(LookupTargetParseError::Invalid);
    }

    parse_ip_cidr_token(normalized).ok_or(LookupTargetParseError::Invalid)
}

pub fn cidr_overlaps(a: CanonicalCidr, b: CanonicalCidr) -> bool {
    network_cidr_overlaps(a, b)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedSourceV4 {
    interval: IntervalU32,
    source_idx: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedSourceV6 {
    interval: IntervalU128,
    source_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct IntervalIndexV4 {
    entries: Vec<IndexedSourceV4>,
    prefix_max_end: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct IntervalIndexV6 {
    entries: Vec<IndexedSourceV6>,
    prefix_max_end: Vec<u128>,
}

impl IntervalIndexV4 {
    fn from_sources(sources: &[LookupSourceEntry]) -> Self {
        let mut entries = sources
            .iter()
            .enumerate()
            .filter_map(|(idx, source)| match source.cidr {
                CanonicalCidr::V4(cidr) => Some(IndexedSourceV4 {
                    interval: ipv4_to_interval(cidr),
                    source_idx: idx,
                }),
                CanonicalCidr::V6(_) => None,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|entry| (entry.interval.start, entry.interval.end));

        let mut prefix_max_end = Vec::with_capacity(entries.len());
        let mut running_max = 0_u32;
        for entry in &entries {
            running_max = running_max.max(entry.interval.end);
            prefix_max_end.push(running_max);
        }

        Self {
            entries,
            prefix_max_end,
        }
    }

    fn overlapping_source_indices(&self, target: IntervalU32) -> impl Iterator<Item = usize> + '_ {
        let upper = self
            .entries
            .partition_point(|entry| entry.interval.start <= target.end);
        let lower = self
            .prefix_max_end
            .partition_point(|max_end| *max_end < target.start);
        let start = lower.min(upper);

        self.entries
            .get(start..upper)
            .into_iter()
            .flatten()
            .filter(move |entry| entry.interval.end >= target.start)
            .map(|entry| entry.source_idx)
    }
}

impl IntervalIndexV6 {
    fn from_sources(sources: &[LookupSourceEntry]) -> Self {
        let mut entries = sources
            .iter()
            .enumerate()
            .filter_map(|(idx, source)| match source.cidr {
                CanonicalCidr::V4(_) => None,
                CanonicalCidr::V6(cidr) => Some(IndexedSourceV6 {
                    interval: ipv6_to_interval(cidr),
                    source_idx: idx,
                }),
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|entry| (entry.interval.start, entry.interval.end));

        let mut prefix_max_end = Vec::with_capacity(entries.len());
        let mut running_max = 0_u128;
        for entry in &entries {
            running_max = running_max.max(entry.interval.end);
            prefix_max_end.push(running_max);
        }

        Self {
            entries,
            prefix_max_end,
        }
    }

    fn overlapping_source_indices(&self, target: IntervalU128) -> impl Iterator<Item = usize> + '_ {
        let upper = self
            .entries
            .partition_point(|entry| entry.interval.start <= target.end);
        let lower = self
            .prefix_max_end
            .partition_point(|max_end| *max_end < target.start);
        let start = lower.min(upper);

        self.entries
            .get(start..upper)
            .into_iter()
            .flatten()
            .filter(move |entry| entry.interval.end >= target.start)
            .map(|entry| entry.source_idx)
    }
}

pub fn run_lookup(targets: &[String], sources: &[LookupSourceEntry]) -> LookupReport {
    let v4_index = IntervalIndexV4::from_sources(sources);
    let v6_index = IntervalIndexV6::from_sources(sources);
    let mut matched_entries = Vec::<(&str, &LookupSourceEntry)>::new();
    let mut invalid_targets = Vec::<&str>::new();

    for target in targets {
        let Ok(parsed) = parse_target_strict(target) else {
            invalid_targets.push(target.as_str());
            continue;
        };

        match parsed {
            CanonicalCidr::V4(cidr) => {
                for source_idx in v4_index.overlapping_source_indices(ipv4_to_interval(cidr)) {
                    if let Some(source) = sources.get(source_idx) {
                        matched_entries.push((target.as_str(), source));
                    }
                }
            }
            CanonicalCidr::V6(cidr) => {
                for source_idx in v6_index.overlapping_source_indices(ipv6_to_interval(cidr)) {
                    if let Some(source) = sources.get(source_idx) {
                        matched_entries.push((target.as_str(), source));
                    }
                }
            }
        }
    }

    matched_entries.sort_unstable_by(|(target_a, source_a), (target_b, source_b)| {
        (
            *target_a,
            source_a.source_label.as_ref(),
            source_a.source_line.as_str(),
            source_a.cidr,
        )
            .cmp(&(
                *target_b,
                source_b.source_label.as_ref(),
                source_b.source_line.as_str(),
                source_b.cidr,
            ))
    });
    matched_entries.dedup_by(|(target_a, source_a), (target_b, source_b)| {
        *target_a == *target_b
            && source_a.source_label == source_b.source_label
            && source_a.source_line == source_b.source_line
            && source_a.cidr == source_b.cidr
    });

    let matches = matched_entries
        .into_iter()
        .map(|(target, source)| LookupMatch {
            target: target.to_string(),
            source_label: source.source_label.to_string(),
            matched_source_entry: source.source_line.clone(),
            matched_cidr: source.cidr,
        })
        .collect();

    invalid_targets.sort_unstable();
    invalid_targets.dedup();

    LookupReport {
        matches,
        invalid_targets: invalid_targets.into_iter().map(str::to_string).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LookupSourceEntry, LookupTargetParseError, cidr_overlaps, parse_target_strict, run_lookup,
    };
    use crate::core::network::{CanonicalCidr, Ipv4Cidr, Ipv6Cidr};

    #[test]
    fn strict_target_parsing_accepts_ip_and_cidr() {
        let host = parse_target_strict("198.51.100.1").expect("host");
        assert_eq!(
            host,
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc6336401, 32))
        );

        let cidr = parse_target_strict("2001:db8::/64").expect("cidr");
        assert_eq!(
            cidr,
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64))
        );
    }

    #[test]
    fn strict_target_parsing_rejects_non_strict_forms() {
        assert_eq!(parse_target_strict(""), Err(LookupTargetParseError::Empty));
        assert_eq!(
            parse_target_strict("10.0.0.1 trailing"),
            Err(LookupTargetParseError::Invalid)
        );
        assert_eq!(
            parse_target_strict("not-an-ip"),
            Err(LookupTargetParseError::Invalid)
        );
    }

    #[test]
    fn overlap_matching_is_family_aware() {
        let v4_a = CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24));
        let v4_b = CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 25));
        let v6 = CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64));

        assert!(cidr_overlaps(v4_a, v4_b));
        assert!(!cidr_overlaps(v4_a, v6));
    }

    #[test]
    fn lookup_reports_matches_and_invalid_targets() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "internal:blocklist".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            },
            LookupSourceEntry {
                source_label: "remote:abcd1234.iplist".into(),
                source_line: "2001:db8::/64".to_string(),
                cidr: CanonicalCidr::V6(Ipv6Cidr::from_parts(
                    0x20010db8000000000000000000000000,
                    64,
                )),
            },
        ];

        let report = run_lookup(
            &[
                "10.0.0.7".to_string(),
                "2001:db8::5".to_string(),
                "invalid".to_string(),
            ],
            &sources,
        );

        assert_eq!(report.invalid_targets, vec!["invalid".to_string()]);
        assert_eq!(report.matches.len(), 2);

        assert_eq!(report.matches[0].target, "10.0.0.7");
        assert_eq!(report.matches[0].source_label, "internal:blocklist");
        assert_eq!(report.matches[0].matched_source_entry, "10.0.0.0/24");

        assert_eq!(report.matches[1].target, "2001:db8::5");
        assert_eq!(report.matches[1].source_label, "remote:abcd1234.iplist");
        assert_eq!(report.matches[1].matched_source_entry, "2001:db8::/64");
    }

    #[test]
    fn lookup_index_handles_non_overlapping_prefix_sections() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:a".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            },
            LookupSourceEntry {
                source_label: "source:b".into(),
                source_line: "10.0.2.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000200, 24)),
            },
            LookupSourceEntry {
                source_label: "source:c".into(),
                source_line: "10.0.4.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000400, 24)),
            },
        ];

        let report = run_lookup(&["10.0.2.7".to_string()], &sources);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].source_label, "source:b");
    }
}
