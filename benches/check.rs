use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use faster_hex::{hex_check_avx2, hex_check_fallback};
use std::time::Duration;

const INPUT: &[&str] = &[
    "Bf9E2d38aceDeeCbbAfccc4B4B7AE",
    "ed136fFDdCcC1DbaFE8CB6Df1AdDBAea44aCcC17b0DbC2741F9CeEeaFbE7A51D",
    " \u{0} 𐀀G\u{0}𐀀 GG\u{0}𐀀G\u{0}Gࠀ\u{0} 𐀀   \u{0}:\u{0}\u{0}gࠀG  G::GG::g𐀀G𐀀\u{0}\u{0}¡𐀀ࠀ\u{0}:GGG Gg𐀀 :\u{0}:gG ¡",
    "ed136fFDdCcC1DbaFE8CB6Df1AdDBAea44aCcC17b0DbC2741F9CeEeaFbE7A51D\u{0} 𐀀G\u{0}𐀀 GG\u{0}𐀀G\u{0}Gࠀ\u{0} 𐀀   \u{0}:\u{0}\u{0}gࠀG  G::GG::g𐀀G𐀀\u{0}\u{0}¡𐀀ࠀ\u{0}:GGG Gg𐀀 :\u{0}:gG ¡",
];

fn bench(c: &mut Criterion) {
    let mut check_fallback_group = c.benchmark_group("check");
    for (idx, input) in INPUT.iter().enumerate() {
        check_fallback_group.bench_with_input(
            BenchmarkId::new("fallback", idx),
            input,
            |b, &input| {
                b.iter(|| {
                    let ret = hex_check_fallback(input.as_bytes());
                    black_box(ret);
                })
            },
        );
        check_fallback_group.bench_with_input(BenchmarkId::new("avx2", idx), input, |b, &input| {
            b.iter(|| {
                let ret = unsafe { hex_check_avx2(input.as_bytes()) };
                black_box(ret);
            })
        });
    }
    check_fallback_group.finish();
}

fn quicker() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = quicker();
    targets = bench
}
criterion_main!(benches);
