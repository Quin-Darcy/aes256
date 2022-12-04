use aes256::*;
use criterion::{criterion_group, criterion_main, Criterion};

fn encrypt_bench(c: &mut Criterion) {
    let key_path: &str = "/home/arbegla/Projects/Rust/libraries/aes256/key.txt";
    let file_path: &str = "/home/arbegla/Projects/Rust/libraries/aes256/src/lib.rs";
    let efile_path: &str = "/home/arbegla/Projects/Rust/libraries/aes256/efile.rs";
    gen_key(key_path);

    c.bench_function(
        "encrypt",
        |b| b.iter(|| aes256::encrypt(file_path, efile_path, key_path))
    );
}

criterion_group!(
    benches,
    encrypt_bench
);

criterion_main!(benches);
