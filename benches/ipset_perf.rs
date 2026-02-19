use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use kidobo::adapters::command_runner::{CommandResult, CommandRunnerError};
use kidobo::adapters::ipset::{
    IpsetCommandRunner, IpsetFamily, IpsetSetSpec, atomic_replace_ipset_values,
};
use kidobo::core::network::{CanonicalCidr, Ipv4Cidr};

fn ipv4_spec() -> IpsetSetSpec {
    IpsetSetSpec {
        set_name: "kidobo".to_string(),
        set_type: "hash:net".to_string(),
        family: IpsetFamily::Inet,
        hashsize: 65_536,
        maxelem: 500_000,
        timeout: 0,
    }
}

fn generate_sorted_ipv4_cidrs(count: usize) -> Vec<CanonicalCidr> {
    let mut cidrs = Vec::with_capacity(count);
    for i in 0..count {
        let idx = i as u32;
        let network = (10_u32 << 24) | ((idx & 0x00ff_ffff) << 8);
        cidrs.push(CanonicalCidr::V4(Ipv4Cidr::from_parts(network, 24)));
    }
    cidrs
}

fn generate_unsorted_with_duplicates(sorted_unique: &[CanonicalCidr]) -> Vec<CanonicalCidr> {
    let mut entries = Vec::with_capacity(sorted_unique.len() + sorted_unique.len() / 4);
    for (idx, cidr) in sorted_unique.iter().copied().enumerate() {
        entries.push(cidr);
        if idx % 4 == 0 {
            entries.push(cidr);
        }
    }
    entries.reverse();
    entries
}

#[derive(Debug, Default, Clone, Copy)]
struct SuccessRunner;

impl IpsetCommandRunner for SuccessRunner {
    fn run(&self, _command: &str, _args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        Ok(CommandResult {
            status: Some(0),
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

fn benchmark_atomic_replace_sorted_unique(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipset_atomic_replace_sorted_unique");
    let runner = SuccessRunner;
    let spec = ipv4_spec();

    for size in [5_000_usize, 20_000_usize] {
        let entries = generate_sorted_ipv4_cidrs(size);
        group.throughput(Throughput::Elements(entries.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &entries, |b, entries| {
            b.iter(|| {
                let result = atomic_replace_ipset_values(&runner, &spec, black_box(entries));
                assert!(result.is_ok());
            });
        });
    }

    group.finish();
}

fn benchmark_atomic_replace_unsorted_with_duplicates(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipset_atomic_replace_unsorted_with_duplicates");
    let runner = SuccessRunner;
    let spec = ipv4_spec();

    for size in [5_000_usize, 20_000_usize] {
        let sorted_unique = generate_sorted_ipv4_cidrs(size);
        let entries = generate_unsorted_with_duplicates(&sorted_unique);
        group.throughput(Throughput::Elements(entries.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &entries, |b, entries| {
            b.iter(|| {
                let result = atomic_replace_ipset_values(&runner, &spec, black_box(entries));
                assert!(result.is_ok());
            });
        });
    }

    group.finish();
}

criterion_group!(
    name = ipset_perf;
    config = Criterion::default().sample_size(20);
    targets =
        benchmark_atomic_replace_sorted_unique,
        benchmark_atomic_replace_unsorted_with_duplicates
);
criterion_main!(ipset_perf);
