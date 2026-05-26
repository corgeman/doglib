/// Argon2id GPU throughput benchmark — deterministic, low-variance.
///
/// Instead of timing random solve attempts, fires a fixed number of kernel
/// launches at an impossible difficulty (255 leading zero bits) so every slot
/// always runs its full batch.  Total hashes / wall-time = true throughput with
/// no search randomness.
///
/// Usage (from the pow_solver crate root):
///   LD_LIBRARY_PATH=/usr/lib/wsl/lib \
///   cargo run --release --features cuda --example argon2_gpu_bench
///
/// Optional env var:
///   GPU_BENCH_DURATION=10   target seconds to run the timed section (default 10)
///   POW_CUDA_SLOTS=N        override concurrent-hash count (default ~70% VRAM)

#[cfg(feature = "cuda")]
fn main() {
    let target_secs: f64 = std::env::var("GPU_BENCH_DURATION")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10.0);

    println!("Argon2id GPU throughput benchmark");
    println!("  target duration: {target_secs:.0}s");
    println!();

    // Calibrate: a few launches to estimate per-launch time, then scale to hit
    // the target duration.  `bench` fires its own warm-up launch internally
    // (excluded from timing), so this also covers GPU init + clock ramp.
    print!("  Calibrating... ");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let (cal_hashes, cal_secs) =
        pow_solver::argon2::bench(5).expect("GPU unavailable — check LD_LIBRARY_PATH on WSL2");
    let secs_per_launch = cal_secs / 5.0;
    let n_launches = ((target_secs / secs_per_launch) as u32).max(5);
    println!(
        "{:.0} hashes/s → running {n_launches} launches (~{target_secs:.0}s)",
        cal_hashes as f64 / cal_secs
    );
    println!();

    let (total_hashes, elapsed) = pow_solver::argon2::bench(n_launches).expect("GPU unavailable");
    let hps = total_hashes as f64 / elapsed;

    println!("  Results");
    println!("  -------");
    println!("  launches : {n_launches}");
    println!("  hashes   : {total_hashes}");
    println!("  time     : {elapsed:.3}s");
    println!("  rate     : {hps:.0} hashes/s");
}

#[cfg(not(feature = "cuda"))]
fn main() {
    eprintln!("Build with --features cuda to run the GPU benchmark.");
    std::process::exit(1);
}
