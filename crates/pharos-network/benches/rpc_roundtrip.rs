use criterion::{Criterion, criterion_group, criterion_main};

fn criterion_benchmark(_c: &mut Criterion) {
    // Phase 4 will fill this in.
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
