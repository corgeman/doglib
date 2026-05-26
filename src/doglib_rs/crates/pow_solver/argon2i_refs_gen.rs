// Build-time generator for the Argon2i data-independent reference-index table
// consumed by cuda/argon2id_pow.cu.
//
// For Argon2id with a single pass (t=1), the first half of memory (slices 0 and
// 1) uses data-independent addressing: each block's reference index depends only
// on the fixed cost parameters, never on the password/salt/counter.  So we
// precompute those 2048 indices once and reuse them for every counter attempt.
// They are a true constant for the bbb a2id.v2 parameters (m=4096 KiB, t=1,
// type=id, lanes=1), so build.rs bakes them into the binary.
//
// This is a scalar Rust port of the host BlaMka precompute originally in
// research/argon_pow/custom_cuda.cu.  It is `include!`d by build.rs only — it is
// not part of the library crate.  All arithmetic uses wrapping ops so the debug
// build-script run never trips overflow checks.

const GEN_QWORDS: usize = 128;
const GEN_BLOCKS: usize = 4096;
const GEN_SEGMENT_LENGTH: u32 = 1024;
const GEN_PASSES: u64 = 1;
const GEN_TYPE_ID: u64 = 2;
const GEN_MEMORY_KIB: u64 = 4096;

fn gen_blamka(x: u64, y: u64) -> u64 {
    let m = 0xffff_ffffu64;
    let lo = (x & m).wrapping_mul(y & m);
    x.wrapping_add(y).wrapping_add(lo.wrapping_mul(2))
}

fn gen_g(v: &mut [u64; GEN_QWORDS], a: usize, b: usize, c: usize, d: usize) {
    v[a] = gen_blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = gen_blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = gen_blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = gen_blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn gen_round16(v: &mut [u64; GEN_QWORDS], i: [usize; 16]) {
    gen_g(v, i[0], i[4], i[8], i[12]);
    gen_g(v, i[1], i[5], i[9], i[13]);
    gen_g(v, i[2], i[6], i[10], i[14]);
    gen_g(v, i[3], i[7], i[11], i[15]);
    gen_g(v, i[0], i[5], i[10], i[15]);
    gen_g(v, i[1], i[6], i[11], i[12]);
    gen_g(v, i[2], i[7], i[8], i[13]);
    gen_g(v, i[3], i[4], i[9], i[14]);
}

fn gen_fill_block(prev: &[u64; GEN_QWORDS], reff: &[u64; GEN_QWORDS], out: &mut [u64; GEN_QWORDS]) {
    let mut v = [0u64; GEN_QWORDS];
    let mut r = [0u64; GEN_QWORDS];
    for k in 0..GEN_QWORDS {
        r[k] = prev[k] ^ reff[k];
        v[k] = r[k];
    }
    // Row pass: each of the 8 rows is 16 consecutive qwords.
    for row in 0..8 {
        let base = row * 16;
        let idx: [usize; 16] = std::array::from_fn(|k| base + k);
        gen_round16(&mut v, idx);
    }
    // Column pass: 8 columns of strided qword pairs.
    for col in 0..8 {
        let i0 = 2 * col;
        let idx: [usize; 16] = [
            i0, i0 + 1, i0 + 16, i0 + 17, i0 + 32, i0 + 33, i0 + 48, i0 + 49,
            i0 + 64, i0 + 65, i0 + 80, i0 + 81, i0 + 96, i0 + 97, i0 + 112, i0 + 113,
        ];
        gen_round16(&mut v, idx);
    }
    for k in 0..GEN_QWORDS {
        out[k] = v[k] ^ r[k];
    }
}

fn gen_next_addresses(address_block: &mut [u64; GEN_QWORDS], input_block: &mut [u64; GEN_QWORDS]) {
    let zero = [0u64; GEN_QWORDS];
    let mut tmp = [0u64; GEN_QWORDS];
    input_block[6] = input_block[6].wrapping_add(1);
    gen_fill_block(&zero, input_block, &mut tmp);
    gen_fill_block(&zero, &tmp, address_block);
}

fn gen_ref_index_alpha(slice: u32, index: u32, pseudo_rand: u32) -> u32 {
    let reference_area_size = (slice * GEN_SEGMENT_LENGTH + index - 1) as u64;
    let mut relative = pseudo_rand as u64;
    relative = relative.wrapping_mul(relative) >> 32;
    relative = reference_area_size - 1 - (reference_area_size.wrapping_mul(relative) >> 32);
    relative as u32
}

/// Compute the Argon2i reference table.  Only slices 0 and 1 (indices 0..2047)
/// are populated; the rest stay 0 (the kernel computes data-dependent refs for
/// slices 2-3 at runtime).
fn generate_argon2i_refs() -> [u32; GEN_BLOCKS] {
    let mut refs = [0u32; GEN_BLOCKS];

    for slice in 0..2u32 {
        let mut input_block = [0u64; GEN_QWORDS];
        let mut address_block = [0u64; GEN_QWORDS];

        input_block[2] = slice as u64;
        input_block[3] = GEN_MEMORY_KIB;
        input_block[4] = GEN_PASSES;
        input_block[5] = GEN_TYPE_ID;

        let start = if slice == 0 { 2u32 } else { 0u32 };
        if slice == 0 {
            gen_next_addresses(&mut address_block, &mut input_block);
        }

        for index in start..GEN_SEGMENT_LENGTH {
            if index % 128 == 0 {
                gen_next_addresses(&mut address_block, &mut input_block);
            }
            let absolute = (slice * GEN_SEGMENT_LENGTH + index) as usize;
            let pseudo = address_block[(index % 128) as usize] as u32;
            refs[absolute] = gen_ref_index_alpha(slice, index, pseudo);
        }
    }

    refs
}

/// Render the table as a Rust source file defining `const ARGON2I_REFS`.
fn emit_argon2i_refs_rs() -> String {
    let refs = generate_argon2i_refs();
    // Structural guard: every data-independent block references an earlier one.
    for i in 2..(2 * GEN_SEGMENT_LENGTH as usize) {
        assert!(refs[i] < i as u32, "argon2i ref invariant violated at {i}: {}", refs[i]);
    }

    let mut s = String::new();
    s.push_str("// @generated by build.rs (see argon2i_refs_gen.rs) — do not edit.\n");
    s.push_str(&format!("const ARGON2I_REFS: [u32; {GEN_BLOCKS}] = [\n"));
    for (i, r) in refs.iter().enumerate() {
        if i % 12 == 0 {
            s.push_str("    ");
        }
        s.push_str(&format!("{r}, "));
        if i % 12 == 11 {
            s.push('\n');
        }
    }
    s.push_str("\n];\n");
    s
}
