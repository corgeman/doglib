//! CUDA Argon2id backend for the bbb `a2id.v2` PoW format.

use super::{
    build_prefix, proof_shape, Challenge, ARGON2I_REFS, ARGON2_BLOCKS, HASH_LEN,
    SUBPROOF_LEN,
};
    use std::sync::Arc;
    use std::sync::OnceLock;

    use cudarc::driver::safe::{CudaContext, CudaFunction, CudaSlice, LaunchConfig, PushKernelArg};
    use cudarc::nvrtc::Ptx;

    const PTX: &str = include_str!(concat!(env!("OUT_DIR"), "/argon2id_pow.ptx"));


    const ARGON2_QWORDS: usize = 128;

    // Launch geometry — must match the kernel (WARP_SIZE * WARPS_PER_BLOCK).
    const THREADS: u32 = 128;
    const WARPS_PER_BLOCK: u32 = 4;
    // Counters per slot per launch.  Total candidates/launch = slots * BATCHES.
    const BATCHES: u64 = 4;

    // 1 MiB-block arena footprint of one concurrent hash: 4096 * 128 * 8 = 4 MiB.
    const BYTES_PER_SLOT: u64 = (ARGON2_BLOCKS * ARGON2_QWORDS * 8) as u64;

    struct GpuState {
        ctx: Arc<CudaContext>,
        func: CudaFunction,
        slots: u32,
    }

    static GPU: OnceLock<Option<GpuState>> = OnceLock::new();

    fn get_gpu() -> Option<&'static GpuState> {
        GPU.get_or_init(|| match init_gpu() {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("[doglib.pow] argon2 GPU init failed, falling back to CPU: {e}");
                None
            }
        })
        .as_ref()
    }

    fn init_gpu() -> Result<GpuState, Box<dyn std::error::Error>> {
        let ctx = CudaContext::new(0)?;
        let module = ctx.load_module(Ptx::from_src(PTX))?;
        let func = module.load_function("argon2id_search_kernel")?;
        let slots = choose_slots(&ctx);
        Ok(GpuState { ctx, func, slots })
    }

    fn choose_slots(ctx: &Arc<CudaContext>) -> u32 {
        if let Ok(v) = std::env::var("POW_CUDA_SLOTS") {
            if let Ok(n) = v.parse::<u32>() {
                if n > 0 {
                    return n.clamp(1, 8192);
                }
            }
        }
        let free = ctx.mem_get_info().map(|(f, _)| f as u64).unwrap_or(0);
        let target = free * 70 / 100;
        (target / BYTES_PER_SLOT).clamp(64, 4096) as u32
    }


    fn de<E: std::fmt::Display>(e: E) -> String {
        format!("cuda error: {e}")
    }

    pub(super) fn available() -> bool {
        get_gpu().is_some()
    }

    /// Solve an `a2id.v2` challenge, returning the dotted-hex solution.
    pub(super) fn solve(challenge: &Challenge, _workers: i64) -> Result<String, String> {
        let Challenge { difficulty, password } = challenge;
        let (proof_count, proof_difficulty) = proof_shape(*difficulty);

        let gpu = get_gpu().ok_or_else(|| "CUDA backend unavailable".to_string())?;
        let stream = gpu.ctx.default_stream();

        // Arena + the constant argon2i reference table: allocate/upload once.
        let arena_len = gpu.slots as usize * ARGON2_BLOCKS * ARGON2_QWORDS;
        let mut arena: CudaSlice<u64> = stream.alloc_zeros(arena_len).map_err(de)?;
        let i_refs: CudaSlice<u32> = stream.clone_htod(&ARGON2I_REFS[..]).map_err(de)?;

        let count: u64 = gpu.slots as u64 * BATCHES;
        let slot_count: u32 = gpu.slots;
        let grid_blocks = (gpu.slots + WARPS_PER_BLOCK - 1) / WARPS_PER_BLOCK;
        let cfg = LaunchConfig {
            block_dim: (THREADS, 1, 1),
            grid_dim: (grid_blocks, 1, 1),
            shared_mem_bytes: 0,
        };

        let mut chain = [0u8; HASH_LEN];
        let mut counters: Vec<String> = Vec::with_capacity(proof_count as usize);
        let pd: u32 = proof_difficulty;

        for index in 0..proof_count {
            let prefix = build_prefix(password, index, &chain);
            let prefix_gpu: CudaSlice<u8> = stream.clone_htod(&prefix[..]).map_err(de)?;

            let mut found_state: CudaSlice<i32> = stream.alloc_zeros(1).map_err(de)?;
            let mut found_counter: CudaSlice<u64> = stream.alloc_zeros(1).map_err(de)?;
            let mut found_digest: CudaSlice<u8> = stream.alloc_zeros(HASH_LEN).map_err(de)?;

            let mut base: u64 = 0;
            let counter = loop {
                stream.memset_zeros(&mut found_state).map_err(de)?;

                unsafe {
                    stream
                        .launch_builder(&gpu.func)
                        .arg(&mut arena)
                        .arg(&i_refs)
                        .arg(&prefix_gpu)
                        .arg(&pd)
                        .arg(&base)
                        .arg(&count)
                        .arg(&slot_count)
                        .arg(&mut found_state)
                        .arg(&mut found_counter)
                        .arg(&mut found_digest)
                        .launch(cfg)
                        .map_err(de)?;
                }
                stream.synchronize().map_err(de)?;

                let st = stream.clone_dtoh(&found_state).map_err(de)?;
                if st[0] != 0 {
                    let c = stream.clone_dtoh(&found_counter).map_err(de)?;
                    let d = stream.clone_dtoh(&found_digest).map_err(de)?;
                    chain.copy_from_slice(&d);
                    break c[0];
                }
                base = base
                    .checked_add(count)
                    .ok_or_else(|| "counter space exhausted".to_string())?;
            };

            counters.push(format!("{counter:x}"));
        }

        Ok(counters.join("."))
    }

    /// Deterministic throughput probe: run `n_launches` kernel launches at an
    /// impossible difficulty (255 leading zero bits — never hit) so every slot
    /// runs its full BATCHES without early-exit.  Returns
    /// `(total_hashes, elapsed_seconds)`.  Used for benchmarking only.
    pub fn bench(n_launches: u32) -> Result<(u64, f64), String> {
        let gpu = get_gpu().ok_or_else(|| "CUDA backend unavailable".to_string())?;
        let stream = gpu.ctx.default_stream();

        let arena_len = gpu.slots as usize * ARGON2_BLOCKS * ARGON2_QWORDS;
        let mut arena: CudaSlice<u64> = stream.alloc_zeros(arena_len).map_err(de)?;
        let i_refs: CudaSlice<u32> = stream.clone_htod(&ARGON2I_REFS[..]).map_err(de)?;
        let prefix_gpu: CudaSlice<u8> = stream.clone_htod(&[0u8; SUBPROOF_LEN][..]).map_err(de)?;
        let mut found_state: CudaSlice<i32> = stream.alloc_zeros(1).map_err(de)?;
        let mut found_counter: CudaSlice<u64> = stream.alloc_zeros(1).map_err(de)?;
        let mut found_digest: CudaSlice<u8> = stream.alloc_zeros(HASH_LEN).map_err(de)?;

        let count: u64 = gpu.slots as u64 * BATCHES;
        let slot_count: u32 = gpu.slots;
        let grid_blocks = (gpu.slots + WARPS_PER_BLOCK - 1) / WARPS_PER_BLOCK;
        let cfg = LaunchConfig {
            block_dim: (THREADS, 1, 1),
            grid_dim: (grid_blocks, 1, 1),
            shared_mem_bytes: 0,
        };
        let pd: u32 = 255; // impossible — every slot runs the full BATCHES

        let run = |arena: &mut CudaSlice<u64>,
                   fs: &mut CudaSlice<i32>,
                   fc: &mut CudaSlice<u64>,
                   fd: &mut CudaSlice<u8>,
                   base: u64| -> Result<(), String> {
            unsafe {
                stream
                    .launch_builder(&gpu.func)
                    .arg(arena)
                    .arg(&i_refs)
                    .arg(&prefix_gpu)
                    .arg(&pd)
                    .arg(&base)
                    .arg(&count)
                    .arg(&slot_count)
                    .arg(fs)
                    .arg(fc)
                    .arg(fd)
                    .launch(cfg)
                    .map_err(de)?;
            }
            Ok(())
        };

        // Warm-up launch (excluded from timing).
        run(&mut arena, &mut found_state, &mut found_counter, &mut found_digest, 0)?;
        stream.synchronize().map_err(de)?;

        let t0 = std::time::Instant::now();
        for i in 0..n_launches as u64 {
            run(&mut arena, &mut found_state, &mut found_counter, &mut found_digest, i * count)?;
        }
        stream.synchronize().map_err(de)?;
        let elapsed = t0.elapsed().as_secs_f64();

        Ok((n_launches as u64 * count, elapsed))
    }
