use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use kidobo::core::lookup::{LookupSourceEntry, run_lookup};
use kidobo::core::network::{
    CanonicalCidr, Ipv4Cidr, Ipv6Cidr, subtract_safelist_ipv4, subtract_safelist_ipv6,
};
use kidobo::core::sync::compute_effective_blocklists;

fn generate_ipv4_cidrs(count: usize) -> Vec<Ipv4Cidr> {
    let mut cidrs = Vec::with_capacity(count);
    for i in 0..count {
        let idx = i as u32;
        let network = (10_u32 << 24) | ((idx & 0x00ff_ffff) << 8);
        cidrs.push(Ipv4Cidr::from_parts(network, 24));
    }
    cidrs
}

fn generate_ipv6_cidrs(count: usize) -> Vec<Ipv6Cidr> {
    let mut cidrs = Vec::with_capacity(count);
    for i in 0..count {
        let idx = i as u128;
        let network = 0x20010db8000000000000000000000000_u128 | (idx << 64);
        cidrs.push(Ipv6Cidr::from_parts(network, 64));
    }
    cidrs
}

fn generate_candidates(v4_count: usize, v6_count: usize) -> Vec<CanonicalCidr> {
    let mut out = Vec::with_capacity(v4_count + v6_count);
    out.extend(
        generate_ipv4_cidrs(v4_count)
            .into_iter()
            .map(CanonicalCidr::V4),
    );
    out.extend(
        generate_ipv6_cidrs(v6_count)
            .into_iter()
            .map(CanonicalCidr::V6),
    );
    out
}

fn benchmark_effective_blocklists(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_effective_blocklists");
    for size in [5_000_usize, 20_000_usize] {
        let candidates = generate_candidates(size, size / 5);
        let safelist = candidates
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, cidr)| (idx % 11 == 0).then_some(cidr))
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(
            (candidates.len() + safelist.len()) as u64,
        ));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                black_box(compute_effective_blocklists(
                    black_box(&candidates),
                    black_box(&safelist),
                    black_box(true),
                ));
            });
        });
    }
    group.finish();
}

fn benchmark_subtract_safelist(c: &mut Criterion) {
    let mut group = c.benchmark_group("subtract_safelist");

    for size in [10_000_usize, 50_000_usize] {
        let candidates_v4 = generate_ipv4_cidrs(size);
        let safelist_v4 = candidates_v4
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, cidr)| (idx % 7 == 0).then_some(cidr))
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(
            (candidates_v4.len() + safelist_v4.len()) as u64,
        ));
        group.bench_with_input(BenchmarkId::new("ipv4", size), &size, |b, _| {
            b.iter(|| {
                black_box(subtract_safelist_ipv4(
                    black_box(&candidates_v4),
                    black_box(&safelist_v4),
                ));
            });
        });
    }

    for size in [2_000_usize, 10_000_usize] {
        let candidates_v6 = generate_ipv6_cidrs(size);
        let safelist_v6 = candidates_v6
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, cidr)| (idx % 9 == 0).then_some(cidr))
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(
            (candidates_v6.len() + safelist_v6.len()) as u64,
        ));
        group.bench_with_input(BenchmarkId::new("ipv6", size), &size, |b, _| {
            b.iter(|| {
                black_box(subtract_safelist_ipv6(
                    black_box(&candidates_v6),
                    black_box(&safelist_v6),
                ));
            });
        });
    }

    group.finish();
}

fn benchmark_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("run_lookup");
    for source_count in [10_000_usize, 25_000_usize] {
        let label: Arc<str> = Arc::from("bench:internal");
        let sources = generate_ipv4_cidrs(source_count)
            .into_iter()
            .map(|cidr| LookupSourceEntry {
                source_label: Arc::clone(&label),
                source_line: cidr.to_string(),
                cidr: CanonicalCidr::V4(cidr),
            })
            .collect::<Vec<_>>();

        let mut targets = Vec::with_capacity(4_000);
        for i in 0..2_000_u32 {
            let host = (10_u32 << 24) | ((i & 0xffff) << 8) | 7;
            targets.push(std::net::Ipv4Addr::from(host).to_string());
        }
        for i in 0..2_000_u32 {
            let host = (198_u32 << 24) | (51_u32 << 16) | ((i & 0xff) << 8) | (i & 0xff);
            targets.push(std::net::Ipv4Addr::from(host).to_string());
        }

        group.throughput(Throughput::Elements((sources.len() + targets.len()) as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(source_count),
            &source_count,
            |b, _| {
                b.iter(|| {
                    black_box(run_lookup(black_box(&targets), black_box(&sources)));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    core_perf,
    benchmark_effective_blocklists,
    benchmark_subtract_safelist,
    benchmark_lookup
);
criterion_main!(core_perf);
