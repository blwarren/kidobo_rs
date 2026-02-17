use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::core::AddressFamily;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanonicalCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl CanonicalCidr {
    pub fn family(self) -> AddressFamily {
        match self {
            Self::V4(_) => AddressFamily::Ipv4,
            Self::V6(_) => AddressFamily::Ipv6,
        }
    }
}

impl std::fmt::Display for CanonicalCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalCidr::V4(cidr) => write!(f, "{cidr}"),
            CanonicalCidr::V6(cidr) => write!(f, "{cidr}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Cidr {
    network: u32,
    prefix: u8,
}

impl Ipv4Cidr {
    pub fn new(address: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix > 32 {
            return None;
        }

        let raw = u32::from(address);
        Some(Self::from_parts(raw, prefix))
    }

    pub fn from_parts(network: u32, prefix: u8) -> Self {
        debug_assert!(prefix <= 32);
        let mask = ipv4_mask(prefix);
        Self {
            network: network & mask,
            prefix,
        }
    }

    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv6Cidr {
    network: u128,
    prefix: u8,
}

impl Ipv6Cidr {
    pub fn new(address: Ipv6Addr, prefix: u8) -> Option<Self> {
        if prefix > 128 {
            return None;
        }

        let raw = u128::from(address);
        Some(Self::from_parts(raw, prefix))
    }

    pub fn from_parts(network: u128, prefix: u8) -> Self {
        debug_assert!(prefix <= 128);
        let mask = ipv6_mask(prefix);
        Self {
            network: network & mask,
            prefix,
        }
    }

    pub fn network(self) -> Ipv6Addr {
        Ipv6Addr::from(self.network)
    }

    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FamilyCidrs {
    pub ipv4: Vec<Ipv4Cidr>,
    pub ipv6: Vec<Ipv6Cidr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IntervalU32 {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IntervalU128 {
    pub start: u128,
    pub end: u128,
}

impl From<Ipv4Cidr> for IntervalU32 {
    fn from(value: Ipv4Cidr) -> Self {
        ipv4_to_interval(value)
    }
}

impl From<Ipv6Cidr> for IntervalU128 {
    fn from(value: Ipv6Cidr) -> Self {
        ipv6_to_interval(value)
    }
}

pub fn parse_ip_cidr_non_strict(input: &str) -> Option<CanonicalCidr> {
    let token = input.split_whitespace().next()?.trim();
    if token.is_empty() {
        return None;
    }

    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(match ip {
            IpAddr::V4(v4) => CanonicalCidr::V4(Ipv4Cidr::new(v4, 32)?),
            IpAddr::V6(v6) => CanonicalCidr::V6(Ipv6Cidr::new(v6, 128)?),
        });
    }

    let (addr_part, prefix_part) = token.split_once('/')?;
    let prefix = prefix_part.parse::<u8>().ok()?;
    let ip = addr_part.parse::<IpAddr>().ok()?;

    match ip {
        IpAddr::V4(v4) => Ipv4Cidr::new(v4, prefix).map(CanonicalCidr::V4),
        IpAddr::V6(v6) => Ipv6Cidr::new(v6, prefix).map(CanonicalCidr::V6),
    }
}

pub fn parse_lines_non_strict<I, S>(inputs: I) -> Vec<CanonicalCidr>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    inputs
        .into_iter()
        .filter_map(|value| parse_ip_cidr_non_strict(value.as_ref()))
        .collect()
}

pub fn split_by_family(cidrs: &[CanonicalCidr]) -> FamilyCidrs {
    let mut separated = FamilyCidrs::default();

    for cidr in cidrs {
        match cidr {
            CanonicalCidr::V4(v4) => separated.ipv4.push(*v4),
            CanonicalCidr::V6(v6) => separated.ipv6.push(*v6),
        }
    }

    separated
}

pub fn dedup_ipv4(mut cidrs: Vec<Ipv4Cidr>) -> Vec<Ipv4Cidr> {
    cidrs.sort_unstable();
    cidrs.dedup();
    cidrs
}

pub fn dedup_ipv6(mut cidrs: Vec<Ipv6Cidr>) -> Vec<Ipv6Cidr> {
    cidrs.sort_unstable();
    cidrs.dedup();
    cidrs
}

pub fn collapse_ipv4(cidrs: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    let deduped = dedup_ipv4(cidrs.to_vec());
    let intervals: Vec<IntervalU32> = deduped.into_iter().map(IntervalU32::from).collect();
    let merged = merge_intervals_u32(&intervals);
    intervals_to_ipv4_cidrs_from_merged(&merged)
}

pub fn collapse_ipv6(cidrs: &[Ipv6Cidr]) -> Vec<Ipv6Cidr> {
    let deduped = dedup_ipv6(cidrs.to_vec());
    let intervals: Vec<IntervalU128> = deduped.into_iter().map(IntervalU128::from).collect();
    let merged = merge_intervals_u128(&intervals);
    intervals_to_ipv6_cidrs_from_merged(&merged)
}

pub fn ipv4_to_interval(cidr: Ipv4Cidr) -> IntervalU32 {
    let start = cidr.network;
    let end = if cidr.prefix == 0 {
        u32::MAX
    } else {
        let host_bits = 32_u32 - u32::from(cidr.prefix);
        let suffix = if host_bits == 0 {
            0
        } else {
            ((1_u64 << host_bits) - 1) as u32
        };
        start | suffix
    };

    IntervalU32 { start, end }
}

pub fn ipv6_to_interval(cidr: Ipv6Cidr) -> IntervalU128 {
    let start = cidr.network;
    let end = if cidr.prefix == 0 {
        u128::MAX
    } else {
        let host_bits = 128_u32 - u32::from(cidr.prefix);
        let suffix = if host_bits == 0 {
            0
        } else {
            (1_u128 << host_bits) - 1
        };
        start | suffix
    };

    IntervalU128 { start, end }
}

pub fn merge_intervals_u32(intervals: &[IntervalU32]) -> Vec<IntervalU32> {
    if intervals.is_empty() {
        return Vec::new();
    }

    let mut sorted = intervals.to_vec();
    sorted.sort_unstable();

    let mut merged = Vec::with_capacity(sorted.len());
    let mut iter = sorted.into_iter();
    let mut current = match iter.next() {
        Some(first) => first,
        None => return Vec::new(),
    };

    for interval in iter {
        if interval.start <= current.end.saturating_add(1) {
            current.end = current.end.max(interval.end);
        } else {
            merged.push(current);
            current = interval;
        }
    }

    merged.push(current);
    merged
}

pub fn merge_intervals_u128(intervals: &[IntervalU128]) -> Vec<IntervalU128> {
    if intervals.is_empty() {
        return Vec::new();
    }

    let mut sorted = intervals.to_vec();
    sorted.sort_unstable();

    let mut merged = Vec::with_capacity(sorted.len());
    let mut iter = sorted.into_iter();
    let mut current = match iter.next() {
        Some(first) => first,
        None => return Vec::new(),
    };

    for interval in iter {
        if interval.start <= current.end.saturating_add(1) {
            current.end = current.end.max(interval.end);
        } else {
            merged.push(current);
            current = interval;
        }
    }

    merged.push(current);
    merged
}

pub fn subtract_safelist_ipv4(candidates: &[Ipv4Cidr], safelist: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    let candidate_intervals = merge_intervals_u32(
        &candidates
            .iter()
            .copied()
            .map(IntervalU32::from)
            .collect::<Vec<_>>(),
    );

    let safe_intervals = merge_intervals_u32(
        &safelist
            .iter()
            .copied()
            .map(IntervalU32::from)
            .collect::<Vec<_>>(),
    );

    let carved = subtract_intervals_u32(&candidate_intervals, &safe_intervals);
    intervals_to_ipv4_cidrs(&carved)
}

pub fn subtract_safelist_ipv6(candidates: &[Ipv6Cidr], safelist: &[Ipv6Cidr]) -> Vec<Ipv6Cidr> {
    let candidate_intervals = merge_intervals_u128(
        &candidates
            .iter()
            .copied()
            .map(IntervalU128::from)
            .collect::<Vec<_>>(),
    );

    let safe_intervals = merge_intervals_u128(
        &safelist
            .iter()
            .copied()
            .map(IntervalU128::from)
            .collect::<Vec<_>>(),
    );

    let carved = subtract_intervals_u128(&candidate_intervals, &safe_intervals);
    intervals_to_ipv6_cidrs(&carved)
}

pub fn intervals_to_ipv4_cidrs(intervals: &[IntervalU32]) -> Vec<Ipv4Cidr> {
    let merged = merge_intervals_u32(intervals);
    intervals_to_ipv4_cidrs_from_merged(&merged)
}

pub fn intervals_to_ipv6_cidrs(intervals: &[IntervalU128]) -> Vec<Ipv6Cidr> {
    let merged = merge_intervals_u128(intervals);
    intervals_to_ipv6_cidrs_from_merged(&merged)
}

fn intervals_to_ipv4_cidrs_from_merged(intervals: &[IntervalU32]) -> Vec<Ipv4Cidr> {
    let mut out = Vec::new();

    for interval in intervals {
        let mut start = interval.start;

        while start <= interval.end {
            let prefix = largest_prefix_u32(start, interval.end);
            out.push(Ipv4Cidr::from_parts(start, prefix));

            if prefix == 0 {
                break;
            }

            let size = 1_u64 << (32_u32 - u32::from(prefix));
            let next = u64::from(start) + size;
            if next > u64::from(u32::MAX) {
                break;
            }
            start = next as u32;
        }
    }

    out
}

fn intervals_to_ipv6_cidrs_from_merged(intervals: &[IntervalU128]) -> Vec<Ipv6Cidr> {
    let mut out = Vec::new();

    for interval in intervals {
        let mut start = interval.start;

        while start <= interval.end {
            let prefix = largest_prefix_u128(start, interval.end);
            out.push(Ipv6Cidr::from_parts(start, prefix));

            if prefix == 0 {
                break;
            }

            let size = 1_u128 << (128_u32 - u32::from(prefix));
            if start > u128::MAX - size {
                break;
            }
            start += size;
        }
    }

    out
}

fn subtract_intervals_u32(base: &[IntervalU32], carve: &[IntervalU32]) -> Vec<IntervalU32> {
    if base.is_empty() {
        return Vec::new();
    }
    if carve.is_empty() {
        return base.to_vec();
    }

    let base = merge_intervals_u32(base);
    let carve = merge_intervals_u32(carve);

    let mut result = Vec::new();
    let mut carve_idx = 0_usize;

    for base_interval in base {
        while carve
            .get(carve_idx)
            .is_some_and(|interval| interval.end < base_interval.start)
        {
            carve_idx += 1;
        }

        let mut fragments = vec![base_interval];
        for carve_interval in carve
            .iter()
            .copied()
            .skip(carve_idx)
            .take_while(|interval| interval.start <= base_interval.end)
        {
            let mut next_fragments = Vec::new();
            for fragment in fragments {
                next_fragments.extend(subtract_one_u32(fragment, carve_interval));
            }
            fragments = next_fragments;
            if fragments.is_empty() {
                break;
            }
        }

        result.extend(fragments);
    }

    result
}

fn subtract_intervals_u128(base: &[IntervalU128], carve: &[IntervalU128]) -> Vec<IntervalU128> {
    if base.is_empty() {
        return Vec::new();
    }
    if carve.is_empty() {
        return base.to_vec();
    }

    let base = merge_intervals_u128(base);
    let carve = merge_intervals_u128(carve);

    let mut result = Vec::new();
    let mut carve_idx = 0_usize;

    for base_interval in base {
        while carve
            .get(carve_idx)
            .is_some_and(|interval| interval.end < base_interval.start)
        {
            carve_idx += 1;
        }

        let mut fragments = vec![base_interval];
        for carve_interval in carve
            .iter()
            .copied()
            .skip(carve_idx)
            .take_while(|interval| interval.start <= base_interval.end)
        {
            let mut next_fragments = Vec::new();
            for fragment in fragments {
                next_fragments.extend(subtract_one_u128(fragment, carve_interval));
            }
            fragments = next_fragments;
            if fragments.is_empty() {
                break;
            }
        }

        result.extend(fragments);
    }

    result
}

fn subtract_one_u32(base: IntervalU32, carve: IntervalU32) -> Vec<IntervalU32> {
    if carve.end < base.start || carve.start > base.end {
        return vec![base];
    }

    if carve.start <= base.start && carve.end >= base.end {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(2);

    if carve.start > base.start {
        out.push(IntervalU32 {
            start: base.start,
            end: carve.start - 1,
        });
    }

    if carve.end < base.end {
        out.push(IntervalU32 {
            start: carve.end + 1,
            end: base.end,
        });
    }

    out
}

fn subtract_one_u128(base: IntervalU128, carve: IntervalU128) -> Vec<IntervalU128> {
    if carve.end < base.start || carve.start > base.end {
        return vec![base];
    }

    if carve.start <= base.start && carve.end >= base.end {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(2);

    if carve.start > base.start {
        out.push(IntervalU128 {
            start: base.start,
            end: carve.start - 1,
        });
    }

    if carve.end < base.end {
        out.push(IntervalU128 {
            start: carve.end + 1,
            end: base.end,
        });
    }

    out
}

fn largest_prefix_u32(start: u32, end: u32) -> u8 {
    let mut prefix = 32_u8;

    while prefix > 0 {
        let next_prefix = prefix - 1;
        if !is_aligned_u32(start, next_prefix) {
            break;
        }
        if block_end_u32(start, next_prefix) > end {
            break;
        }
        prefix = next_prefix;
    }

    prefix
}

fn largest_prefix_u128(start: u128, end: u128) -> u8 {
    let mut prefix = 128_u8;

    while prefix > 0 {
        let next_prefix = prefix - 1;
        if !is_aligned_u128(start, next_prefix) {
            break;
        }
        if block_end_u128(start, next_prefix) > end {
            break;
        }
        prefix = next_prefix;
    }

    prefix
}

fn is_aligned_u32(start: u32, prefix: u8) -> bool {
    if prefix == 0 {
        return start == 0;
    }

    let host_bits = 32_u32 - u32::from(prefix);
    let host_mask = ((1_u64 << host_bits) - 1) as u32;
    (start & host_mask) == 0
}

fn is_aligned_u128(start: u128, prefix: u8) -> bool {
    if prefix == 0 {
        return start == 0;
    }

    let host_bits = 128_u32 - u32::from(prefix);
    let host_mask = (1_u128 << host_bits) - 1;
    (start & host_mask) == 0
}

fn block_end_u32(start: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        u32::MAX
    } else {
        let host_bits = 32_u32 - u32::from(prefix);
        start.saturating_add(((1_u64 << host_bits) - 1) as u32)
    }
}

fn block_end_u128(start: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        u128::MAX
    } else {
        let host_bits = 128_u32 - u32::from(prefix);
        start.saturating_add((1_u128 << host_bits) - 1)
    }
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32_u32 - u32::from(prefix))
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128_u32 - u32::from(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalCidr, IntervalU32, IntervalU128, Ipv4Cidr, Ipv6Cidr, collapse_ipv4, collapse_ipv6,
        intervals_to_ipv4_cidrs, intervals_to_ipv6_cidrs, ipv4_to_interval, ipv6_to_interval,
        merge_intervals_u32, merge_intervals_u128, parse_ip_cidr_non_strict,
        parse_lines_non_strict, split_by_family, subtract_safelist_ipv4, subtract_safelist_ipv6,
    };

    #[test]
    fn parse_non_strict_accepts_hosts_and_canonicalizes_networks() {
        let host = parse_ip_cidr_non_strict("10.0.0.1").expect("parse host");
        assert_eq!(
            host,
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000001, 32))
        );

        let cidr = parse_ip_cidr_non_strict("10.0.0.42/24").expect("parse cidr");
        assert_eq!(
            cidr,
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24))
        );

        assert!(parse_ip_cidr_non_strict("not-an-ip").is_none());
        assert!(parse_ip_cidr_non_strict(" ").is_none());
    }

    #[test]
    fn split_by_family_is_strict() {
        let parsed = parse_lines_non_strict([
            "10.0.0.1",
            "2001:db8::1",
            "invalid",
            "198.51.100.0/24 trailing",
        ]);

        let separated = split_by_family(&parsed);
        assert_eq!(separated.ipv4.len(), 2);
        assert_eq!(separated.ipv6.len(), 1);
    }

    #[test]
    fn collapse_ipv4_merges_overlap_and_adjacency() {
        let collapsed = collapse_ipv4(&[
            Ipv4Cidr::from_parts(0x0a000000, 25),
            Ipv4Cidr::from_parts(0x0a000080, 25),
            Ipv4Cidr::from_parts(0x0a000000, 24),
        ]);

        assert_eq!(collapsed, vec![Ipv4Cidr::from_parts(0x0a000000, 24)]);
    }

    #[test]
    fn collapse_ipv6_merges_adjacent_networks() {
        let collapsed = collapse_ipv6(&[
            Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 65),
            Ipv6Cidr::from_parts(0x20010db8000000008000000000000000, 65),
        ]);

        assert_eq!(
            collapsed,
            vec![Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64)]
        );
    }

    #[test]
    fn interval_conversion_is_correct_for_ipv4_and_ipv6() {
        let v4_interval = ipv4_to_interval(Ipv4Cidr::from_parts(0xc0000200, 24));
        assert_eq!(
            v4_interval,
            IntervalU32 {
                start: 0xc0000200,
                end: 0xc00002ff,
            }
        );

        let v6_interval = ipv6_to_interval(Ipv6Cidr::from_parts(
            0x20010db8000000000000000000000000,
            126,
        ));
        assert_eq!(
            v6_interval,
            IntervalU128 {
                start: 0x20010db8000000000000000000000000,
                end: 0x20010db8000000000000000000000003,
            }
        );
    }

    #[test]
    fn merge_intervals_handles_adjacency() {
        let merged_v4 = merge_intervals_u32(&[
            IntervalU32 { start: 10, end: 20 },
            IntervalU32 { start: 21, end: 30 },
        ]);
        assert_eq!(merged_v4, vec![IntervalU32 { start: 10, end: 30 }]);

        let merged_v6 = merge_intervals_u128(&[
            IntervalU128 {
                start: 100,
                end: 120,
            },
            IntervalU128 {
                start: 121,
                end: 130,
            },
        ]);
        assert_eq!(
            merged_v6,
            vec![IntervalU128 {
                start: 100,
                end: 130
            }]
        );
    }

    #[test]
    fn safelist_subtraction_carves_ipv4_ranges() {
        let carved = subtract_safelist_ipv4(
            &[Ipv4Cidr::from_parts(0x0a000000, 24)],
            &[Ipv4Cidr::from_parts(0x0a000000, 25)],
        );

        assert_eq!(carved, vec![Ipv4Cidr::from_parts(0x0a000080, 25)]);
    }

    #[test]
    fn safelist_subtraction_carves_ipv6_ranges() {
        let carved = subtract_safelist_ipv6(
            &[Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000000,
                127,
            )],
            &[Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000000,
                128,
            )],
        );

        assert_eq!(
            carved,
            vec![Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000001,
                128
            )]
        );
    }

    #[test]
    fn minimal_cidr_regeneration_from_intervals() {
        let cidrs = intervals_to_ipv4_cidrs(&[IntervalU32 {
            start: 0x0a000002,
            end: 0x0a000005,
        }]);

        assert_eq!(
            cidrs,
            vec![
                Ipv4Cidr::from_parts(0x0a000002, 31),
                Ipv4Cidr::from_parts(0x0a000004, 31),
            ]
        );

        let cidrs_v6 = intervals_to_ipv6_cidrs(&[IntervalU128 {
            start: 0x20010db8000000000000000000000002,
            end: 0x20010db8000000000000000000000003,
        }]);
        assert_eq!(
            cidrs_v6,
            vec![Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000002,
                127
            )]
        );
    }

    #[test]
    fn parse_lines_non_strict_ignores_invalid_lines() {
        let parsed = parse_lines_non_strict(["10.0.0.1", "not-valid", "2001:db8::/32"]);
        assert_eq!(parsed.len(), 2);
    }
}
