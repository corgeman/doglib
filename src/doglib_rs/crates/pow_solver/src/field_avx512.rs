//! AVX512 IFMA accelerated 1279-bit field arithmetic.
//!
//! Uses 52-bit limbs in 512-bit zmm registers with IFMA multiply-add instructions
//! for the inner squaring kernel. All loops are fully unrolled at compile time via
//! const generics. Sliding windows are constructed from registers via valignq to
//! avoid store-forwarding stalls from unaligned memory loads.

use crate::field::Fe1279;

const LIMBS: usize = 25;
const MASK52: u64 = (1u64 << 52) - 1;
const MASK31: u64 = (1u64 << 31) - 1;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[repr(C, align(64))]
struct AlignedBuf {
    buf: [u64; 48],
}

#[cfg(test)]
#[target_feature(enable = "avx512f,avx512ifma")]
pub unsafe fn single_square_mod(fe: &mut Fe1279) {
    let mut ab = AlignedBuf { buf: [0u64; 48] };
    ab.buf[8..8 + LIMBS].copy_from_slice(&fe.limb);
    avx512_square_mod(&mut ab);
    fe.limb.copy_from_slice(&ab.buf[8..8 + LIMBS]);
}

#[cfg(test)]
#[target_feature(enable = "avx512f,avx512ifma")]
pub unsafe fn debug_compare_squarings(fe: &Fe1279, n: usize) -> Option<usize> {
    let mut scalar = *fe;
    let mut ab = AlignedBuf { buf: [0u64; 48] };
    ab.buf[8..8 + LIMBS].copy_from_slice(&fe.limb);

    for step in 0..n {
        scalar.square_mod();
        avx512_square_mod(&mut ab);
        for i in 0..LIMBS {
            if scalar.limb[i] != ab.buf[8 + i] {
                return Some(step);
            }
        }
    }
    None
}

/// # Safety
/// Caller must ensure AVX512F and AVX512IFMA are supported.
#[target_feature(enable = "avx512f,avx512ifma")]
pub unsafe fn solve_inner(fe: &mut Fe1279, difficulty: u32) {
    let mut ab = AlignedBuf { buf: [0u64; 48] };
    ab.buf[8..8 + LIMBS].copy_from_slice(&fe.limb);

    for _ in 0..difficulty {
        for _ in 0..1277 {
            avx512_square_mod(&mut ab);
        }
        ab.buf[8] ^= 1;
    }

    fe.limb.copy_from_slice(&ab.buf[8..8 + LIMBS]);
}

// ---- Compile-time mask computation ----

const fn upper_triangle_mask(idx: i32, i: i32) -> u8 {
    if idx < i {
        0xFF
    } else {
        let shift = (idx - i + 1) as u32;
        if shift >= 8 {
            0
        } else {
            0xFFu8 << shift
        }
    }
}

// ---- Register-based window construction ----

/// Construct a sliding 8-element window at position I entirely from registers.
/// Uses valignq to combine adjacent clumps, avoiding store-forwarding stalls
/// that occur with unaligned loads from recently-stored memory.
#[inline(always)]
unsafe fn make_window<const I: i32>(clumps: &[__m512i; 4], zero: __m512i) -> __m512i {
    const { assert!(I >= -7 && I <= 24) };

    if I < 0 {
        let hi = clumps[0];
        match I {
            -1 => _mm512_alignr_epi64(hi, zero, 7),
            -2 => _mm512_alignr_epi64(hi, zero, 6),
            -3 => _mm512_alignr_epi64(hi, zero, 5),
            -4 => _mm512_alignr_epi64(hi, zero, 4),
            -5 => _mm512_alignr_epi64(hi, zero, 3),
            -6 => _mm512_alignr_epi64(hi, zero, 2),
            -7 => _mm512_alignr_epi64(hi, zero, 1),
            _ => core::hint::unreachable_unchecked(),
        }
    } else if I & 7 == 0 {
        clumps[(I / 8) as usize]
    } else {
        let lo = clumps[(I / 8) as usize];
        let hi = clumps[(I / 8 + 1) as usize];
        match I & 7 {
            1 => _mm512_alignr_epi64(hi, lo, 1),
            2 => _mm512_alignr_epi64(hi, lo, 2),
            3 => _mm512_alignr_epi64(hi, lo, 3),
            4 => _mm512_alignr_epi64(hi, lo, 4),
            5 => _mm512_alignr_epi64(hi, lo, 5),
            6 => _mm512_alignr_epi64(hi, lo, 6),
            7 => _mm512_alignr_epi64(hi, lo, 7),
            _ => core::hint::unreachable_unchecked(),
        }
    }
}

// ---- Unrolled cross-term accumulation ----
// Each (I, J) pair is monomorphized at compile time, so bounds checks,
// mask computations, and dead code are all resolved statically.
// Both unmasked and masked broadcasts use inline asm with {1to8} memory
// operands to avoid materializing temporary broadcast vectors in ZMM regs.

#[inline(always)]
unsafe fn accumulate_pair<const I: i32, const J: usize>(
    data: *const u64,
    m1: __m512i,
    acc_lo: &mut [__m512i; 7],
    acc_hi: &mut [__m512i; 7],
) {
    const fn lo_idx(i: i32, j: usize) -> i32 {
        (j as i32) * 8 - i
    }
    const fn hi_idx(i: i32, j: usize) -> i32 {
        (j as i32) * 8 - i - 1
    }

    // Lo-half: lo52(data[I+e] * data[lo_idx])
    {
        const { assert!(J < 7) };
        let li = lo_idx(I, J);
        if li >= 0 && li <= 24 {
            let sel = upper_triangle_mask(li, I);
            if sel != 0 {
                let ptr = data.add(li as usize);
                if sel == 0xFF {
                    core::arch::asm!(
                        "vpmadd52luq {dst}, {src}, [{ptr}]{{1to8}}",
                        dst = inout(zmm_reg) acc_lo[J],
                        src = in(zmm_reg) m1,
                        ptr = in(reg) ptr,
                        options(nostack, readonly),
                    );
                } else {
                    core::arch::asm!(
                        "vpmadd52luq {dst}{{{mask}}}, {src}, [{ptr}]{{1to8}}",
                        dst = inout(zmm_reg) acc_lo[J],
                        mask = in(kreg) sel,
                        src = in(zmm_reg) m1,
                        ptr = in(reg) ptr,
                        options(nostack, readonly),
                    );
                }
            }
        }
    }

    // Hi-half: hi52(data[I+e] * data[hi_idx])
    {
        let hi = hi_idx(I, J);
        if hi >= 0 && hi <= 24 {
            let sel = upper_triangle_mask(hi, I);
            if sel != 0 {
                let ptr = data.add(hi as usize);
                if sel == 0xFF {
                    core::arch::asm!(
                        "vpmadd52huq {dst}, {src}, [{ptr}]{{1to8}}",
                        dst = inout(zmm_reg) acc_hi[J],
                        src = in(zmm_reg) m1,
                        ptr = in(reg) ptr,
                        options(nostack, readonly),
                    );
                } else {
                    core::arch::asm!(
                        "vpmadd52huq {dst}{{{mask}}}, {src}, [{ptr}]{{1to8}}",
                        dst = inout(zmm_reg) acc_hi[J],
                        mask = in(kreg) sel,
                        src = in(zmm_reg) m1,
                        ptr = in(reg) ptr,
                        options(nostack, readonly),
                    );
                }
            }
        }
    }
}

/// Process one sliding window position. J-loop is fully unrolled via 7 explicit calls.
#[inline(always)]
unsafe fn process_window<const I: i32>(
    data: *const u64,
    m1: __m512i,
    acc_lo: &mut [__m512i; 7],
    acc_hi: &mut [__m512i; 7],
) {
    accumulate_pair::<I, 0>(data, m1, acc_lo, acc_hi);
    accumulate_pair::<I, 1>(data, m1, acc_lo, acc_hi);
    accumulate_pair::<I, 2>(data, m1, acc_lo, acc_hi);
    accumulate_pair::<I, 3>(data, m1, acc_lo, acc_hi);
    accumulate_pair::<I, 4>(data, m1, acc_lo, acc_hi);
    accumulate_pair::<I, 5>(data, m1, acc_lo, acc_hi);
    accumulate_pair::<I, 6>(data, m1, acc_lo, acc_hi);
}

// ---- Main squaring kernel ----

/// Macro to call process_window for all 32 values of I (24 down to -7).
/// Windows are constructed from register-held clumps via valignq.
macro_rules! unroll_windows {
    ($data:expr, $clumps:expr, $zero:expr, $acc_lo:expr, $acc_hi:expr, $($i:literal),* $(,)?) => {
        $(
            {
                let m1 = make_window::<$i>($clumps, $zero);
                process_window::<$i>($data, m1, $acc_lo, $acc_hi);
            }
        )*
    };
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
unsafe fn avx512_square_mod(ab: &mut AlignedBuf) {
    let data = ab.buf.as_ptr().add(8);

    let clumps: [__m512i; 4] = [
        _mm512_load_si512(data.add(0) as *const _),
        _mm512_load_si512(data.add(8) as *const _),
        _mm512_load_si512(data.add(16) as *const _),
        _mm512_load_si512(data.add(24) as *const _),
    ];

    let zero = _mm512_setzero_si512();
    let mut acc_lo = [zero; 7];
    let mut acc_hi = [zero; 7];

    unroll_windows!(
        data, &clumps, zero, &mut acc_lo, &mut acc_hi,
        24, 23, 22, 21, 20, 19, 18, 17,
        16, 15, 14, 13, 12, 11, 10, 9,
        8, 7, 6, 5, 4, 3, 2, 1,
        0, -1, -2, -3, -4, -5, -6, -7,
    );

    // Fold lo + hi and double (cross-terms appear once, need 2x for symmetry)
    let mut accum = [zero; 7];
    for j in 0..7 {
        accum[j] = _mm512_add_epi64(acc_lo[j], acc_hi[j]);
        accum[j] = _mm512_add_epi64(accum[j], accum[j]);
    }

    // Add diagonal terms: a[i]^2
    {
        let diag_lo = _mm512_madd52lo_epu64(zero, clumps[0], clumps[0]);
        let diag_hi = _mm512_madd52hi_epu64(zero, clumps[0], clumps[0]);
        let shuf_lo = _mm512_set_epi64(11, 3, 10, 2, 9, 1, 8, 0);
        let shuf_hi = _mm512_set_epi64(15, 7, 14, 6, 13, 5, 12, 4);
        accum[0] = _mm512_add_epi64(
            accum[0],
            _mm512_permutex2var_epi64(diag_lo, shuf_lo, diag_hi),
        );
        accum[1] = _mm512_add_epi64(
            accum[1],
            _mm512_permutex2var_epi64(diag_lo, shuf_hi, diag_hi),
        );
    }
    {
        let diag_lo = _mm512_madd52lo_epu64(zero, clumps[1], clumps[1]);
        let diag_hi = _mm512_madd52hi_epu64(zero, clumps[1], clumps[1]);
        let shuf_lo = _mm512_set_epi64(11, 3, 10, 2, 9, 1, 8, 0);
        let shuf_hi = _mm512_set_epi64(15, 7, 14, 6, 13, 5, 12, 4);
        accum[2] = _mm512_add_epi64(
            accum[2],
            _mm512_permutex2var_epi64(diag_lo, shuf_lo, diag_hi),
        );
        accum[3] = _mm512_add_epi64(
            accum[3],
            _mm512_permutex2var_epi64(diag_lo, shuf_hi, diag_hi),
        );
    }
    {
        let diag_lo = _mm512_madd52lo_epu64(zero, clumps[2], clumps[2]);
        let diag_hi = _mm512_madd52hi_epu64(zero, clumps[2], clumps[2]);
        let shuf_lo = _mm512_set_epi64(11, 3, 10, 2, 9, 1, 8, 0);
        let shuf_hi = _mm512_set_epi64(15, 7, 14, 6, 13, 5, 12, 4);
        accum[4] = _mm512_add_epi64(
            accum[4],
            _mm512_permutex2var_epi64(diag_lo, shuf_lo, diag_hi),
        );
        accum[5] = _mm512_add_epi64(
            accum[5],
            _mm512_permutex2var_epi64(diag_lo, shuf_hi, diag_hi),
        );
    }
    {
        let diag_lo = _mm512_madd52lo_epu64(zero, clumps[3], clumps[3]);
        let diag_hi = _mm512_madd52hi_epu64(zero, clumps[3], clumps[3]);
        let shuf_lo = _mm512_set_epi64(11, 3, 10, 2, 9, 1, 8, 0);
        accum[6] = _mm512_add_epi64(
            accum[6],
            _mm512_permutex2var_epi64(diag_lo, shuf_lo, diag_hi),
        );
    }

    // --- Mersenne reduction: fold bits >= 1279 back ---
    let mut high = [zero; 4];
    {
        let mut prev = zero;
        for idx in (0..4i32).rev() {
            let src = accum[(idx + 3) as usize];
            let down_31 = _mm512_srli_epi64(src, 31);
            let lo_31 = _mm512_and_si512(src, _mm512_set1_epi64(MASK31 as i64));
            let up_21 = _mm512_slli_epi64(lo_31, 21);
            high[idx as usize] =
                _mm512_add_epi64(_mm512_alignr_epi64(prev, up_21, 1), down_31);
            prev = up_21;
        }
    }

    accum[3] = _mm512_and_si512(
        accum[3],
        _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, MASK31 as i64),
    );

    for idx in 0..4 {
        accum[idx] = _mm512_add_epi64(accum[idx], high[idx]);
    }

    // Carry propagation
    let low_52 = _mm512_set1_epi64(MASK52 as i64);
    let hi_12 = _mm512_set1_epi64(!(MASK52 as i64));
    loop {
        let mut any_overflow = zero;
        let mut group_out = zero;
        for idx in 0..4 {
            let carries = _mm512_srli_epi64(accum[idx], 52);
            let carries_into = _mm512_alignr_epi64(carries, group_out, 7);
            accum[idx] =
                _mm512_add_epi64(_mm512_and_si512(accum[idx], low_52), carries_into);
            group_out = carries;
            any_overflow =
                _mm512_or_si512(any_overflow, _mm512_and_si512(accum[idx], hi_12));
        }
        if _mm512_test_epi64_mask(any_overflow, hi_12) == 0 {
            break;
        }
    }

    // Mersenne wrap: if bit 1279 is set, fold it back
    let bit_1279 = _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, (1u64 << 31) as i64);
    let mask_31 = _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, MASK31 as i64);
    let cmp = _mm512_and_si512(accum[3], bit_1279);
    accum[0] = _mm512_add_epi64(accum[0], _mm512_srli_epi64(cmp, 31));
    accum[3] = _mm512_and_si512(accum[3], mask_31);

    // Store result
    let data_mut = ab.buf.as_mut_ptr().add(8);
    _mm512_store_si512(data_mut.add(0) as *mut _, accum[0]);
    _mm512_store_si512(data_mut.add(8) as *mut _, accum[1]);
    _mm512_store_si512(data_mut.add(16) as *mut _, accum[2]);
    _mm512_store_si512(data_mut.add(24) as *mut _, accum[3]);
}
