use crate::core::network::{
    CanonicalCidr, Ipv4Cidr, Ipv6Cidr, collapse_ipv4, collapse_ipv6, split_by_family,
    subtract_safelist_ipv4, subtract_safelist_ipv6,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EffectiveBlocklists {
    pub ipv4: Vec<Ipv4Cidr>,
    pub ipv6: Vec<Ipv6Cidr>,
}

pub fn compute_effective_blocklists(
    candidates: &[CanonicalCidr],
    safelist: &[CanonicalCidr],
    enable_ipv6: bool,
) -> EffectiveBlocklists {
    let candidate_family = split_by_family(candidates);
    let safelist_family = split_by_family(safelist);

    let collapsed_v4 = collapse_ipv4(&candidate_family.ipv4);
    let collapsed_safe_v4 = collapse_ipv4(&safelist_family.ipv4);
    let mut effective_v4 = subtract_safelist_ipv4(&collapsed_v4, &collapsed_safe_v4);
    effective_v4.sort_unstable();

    let mut effective_v6 = if enable_ipv6 {
        let collapsed_v6 = collapse_ipv6(&candidate_family.ipv6);
        let collapsed_safe_v6 = collapse_ipv6(&safelist_family.ipv6);
        let mut carved_v6 = subtract_safelist_ipv6(&collapsed_v6, &collapsed_safe_v6);
        carved_v6.sort_unstable();
        carved_v6
    } else {
        Vec::new()
    };

    effective_v4.dedup();
    effective_v6.dedup();

    EffectiveBlocklists {
        ipv4: effective_v4,
        ipv6: effective_v6,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use crate::core::network::{CanonicalCidr, Ipv4Cidr, Ipv6Cidr};

    use super::compute_effective_blocklists;

    #[test]
    fn pipeline_collapses_and_carves_per_family() {
        let candidates = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 25)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 25)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64)),
        ];
        let safelist = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 25)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 65)),
        ];

        let effective = compute_effective_blocklists(&candidates, &safelist, true);

        assert_eq!(
            effective.ipv4,
            vec![Ipv4Cidr::from_parts(0x0a000080, 25)],
            "collapsed /24 should be carved by /25 safelist"
        );
        assert_eq!(
            effective.ipv6,
            vec![
                Ipv6Cidr::new(
                    "2001:db8:0:0:8000::"
                        .parse::<Ipv6Addr>()
                        .expect("valid ipv6"),
                    65
                )
                .expect("valid cidr")
            ],
            "v6 /64 should be carved by /65 safelist"
        );
    }

    #[test]
    fn ipv6_disable_drops_ipv6_output() {
        let candidates = vec![CanonicalCidr::V6(Ipv6Cidr::from_parts(
            0x20010db8000000000000000000000000,
            64,
        ))];

        let effective = compute_effective_blocklists(&candidates, &[], false);
        assert!(effective.ipv6.is_empty());
    }
}
