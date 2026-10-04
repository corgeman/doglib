//! AVX-512 IFMA arithmetic modulo 2^1279 - 1, using 25 radix-2^52 limbs.
//! Even and odd product coefficients use register windows rather than scalar
//! broadcasts. The 256-bit IFMA form avoids wasted lanes on triangular products.

use super::field::Fe1279;
use core::arch::x86_64::*;

const MASK52: u64 = (1u64 << 52) - 1;
const MASK31: u64 = (1u64 << 31) - 1;

#[inline]
pub(crate) fn is_supported() -> bool {
    std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512ifma")
        && std::arch::is_x86_feature_detected!("avx512vl")
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512vl")]
unsafe fn load(fe: &Fe1279) -> [__m256i; 7] {
    let p = fe.limb.as_ptr();
    // Fe1279 is 64-byte aligned; only the final limb is accessible to the
    // masked load. Zero padding supplies out-of-range convolution operands.
    let mut x = [_mm256_setzero_si256(); 7];
    for j in 0..6 {
        x[j] = _mm256_load_si256(p.add(4 * j).cast());
    }
    x[6] = _mm256_maskz_loadu_epi64(1, p.add(24).cast());
    x
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512vl")]
unsafe fn store(fe: &mut Fe1279, x: [__m256i; 7]) {
    let p = fe.limb.as_mut_ptr();
    for j in 0..6 {
        _mm256_store_si256(p.add(4 * j).cast(), x[j]);
    }
    _mm256_mask_storeu_epi64(p.add(24).cast(), 1, x[6]);
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512vl")]
unsafe fn canonicalize(x: &mut [__m256i; 7]) {
    let mut all = x[0];
    for j in 1..6 {
        all = _mm256_and_si256(all, x[j]);
    }
    if _mm256_cmpeq_epi64_mask(all, _mm256_set1_epi64x(MASK52 as i64)) == 0xf
        && _mm256_cmpeq_epi64_mask(x[6], _mm256_set1_epi64x(MASK31 as i64)) & 1 != 0
    {
        *x = [_mm256_setzero_si256(); 7];
    }
}

#[cfg(test)]
#[target_feature(enable = "avx512f,avx512ifma,avx512vl")]
pub unsafe fn single_square_mod(fe: &mut Fe1279) {
    let mut x = square(load(fe));
    canonicalize(&mut x);
    store(fe, x);
}

#[cfg(test)]
#[target_feature(enable = "avx512f,avx512ifma,avx512vl")]
pub unsafe fn debug_compare_squarings(fe: &Fe1279, n: usize) -> Option<usize> {
    let mut scalar = *fe;
    let mut avx = *fe;
    for step in 0..n {
        scalar.square_mod();
        single_square_mod(&mut avx);
        if scalar.limb != avx.limb {
            return Some(step);
        }
    }
    None
}

/// # Safety
/// Caller must ensure AVX512F, AVX512IFMA and AVX512VL are supported. Input
/// limbs must fit in 52 bits, with only 31 bits in the final limb.
#[target_feature(enable = "avx512f,avx512ifma,avx512vl")]
pub unsafe fn solve_inner(fe: &mut Fe1279, difficulty: u32) {
    let mut x = load(fe);
    let one = _mm256_set_epi64x(0, 0, 0, 1);
    for _ in 0..difficulty {
        for _ in 0..1277 {
            x = square(x);
        }
        // p is a valid redundant zero during squaring, but not during XOR.
        canonicalize(&mut x);
        x[0] = _mm256_xor_si256(x[0], one);
    }
    store(fe, x);
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512vl")]
unsafe fn window<const I: i32>(x: &[__m256i; 7]) -> __m256i {
    const { assert!(I >= -3 && I <= 24) };
    let zero = _mm256_setzero_si256();
    let lo = if I < 0 { zero } else { x[(I / 4) as usize] };
    let hi = if I < 0 {
        x[0]
    } else if I < 24 {
        x[(I / 4 + 1) as usize]
    } else {
        zero
    };
    match I & 3 {
        0 => lo,
        1 => _mm256_alignr_epi64(hi, lo, 1),
        2 => _mm256_alignr_epi64(hi, lo, 2),
        3 => _mm256_alignr_epi64(hi, lo, 3),
        _ => unreachable!(),
    }
}

// Four independent IFMA chains trade extra additions for lower dependency
// latency. Offsets and accumulator indices are compile-time constants.
macro_rules! products {
    ($x:expr; $base:literal, $parity:literal; $($t:literal),+ $(,)?) => {{
        let mut lo = [_mm256_setzero_si256(); 4];
        let mut hi = [_mm256_setzero_si256(); 4];
        $(
            let a = window::<{ $base - $t }>(&$x);
            let b = window::<{ $base + $t + $parity }>(&$x);
            lo[$t & 3] = _mm256_madd52lo_epu64(lo[$t & 3], a, b);
            hi[$t & 3] = _mm256_madd52hi_epu64(hi[$t & 3], a, b);
        )+
        (
            _mm256_add_epi64(_mm256_add_epi64(lo[0], lo[1]), _mm256_add_epi64(lo[2], lo[3])),
            _mm256_add_epi64(_mm256_add_epi64(hi[0], hi[1]), _mm256_add_epi64(hi[2], hi[3])),
        )
    }};
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512vl")]
unsafe fn square(x: [__m256i; 7]) -> [__m256i; 7] {
    // Coefficient 2k pairs a[k-t] with a[k+t]; coefficient 2k+1 pairs
    // a[k-t] with a[k+t+1]. Padding eliminates triangular IFMA masks.
    let zero = _mm256_setzero_si256();
    let even = [
        products!(x; 0, 0; 1, 2, 3),
        products!(x; 4, 0; 1, 2, 3, 4, 5, 6, 7),
        products!(x; 8, 0; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
        products!(x; 12, 0; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
        products!(x; 16, 0; 1, 2, 3, 4, 5, 6, 7, 8),
        products!(x; 20, 0; 1, 2, 3, 4),
        (zero, zero),
    ];
    let odd = [
        products!(x; 0, 1; 0, 1, 2, 3),
        products!(x; 4, 1; 0, 1, 2, 3, 4, 5, 6, 7),
        products!(x; 8, 1; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
        products!(x; 12, 1; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
        products!(x; 16, 1; 0, 1, 2, 3, 4, 5, 6, 7),
        products!(x; 20, 1; 0, 1, 2, 3),
        (zero, zero),
    ];
    let mut e = [zero; 7];
    let mut o = [zero; 7];
    let mut prev = zero;
    for j in 0..7 {
        let el = _mm256_madd52lo_epu64(_mm256_add_epi64(even[j].0, even[j].0), x[j], x[j]);
        let eh = _mm256_madd52hi_epu64(_mm256_add_epi64(even[j].1, even[j].1), x[j], x[j]);
        let ol = _mm256_add_epi64(odd[j].0, odd[j].0);
        let oh = _mm256_add_epi64(odd[j].1, odd[j].1);
        e[j] = _mm256_add_epi64(el, _mm256_alignr_epi64(oh, prev, 3));
        o[j] = _mm256_add_epi64(ol, eh);
        prev = oh;
    }

    // Fold at bit 1279 before interleaving. Shifting by 24 limbs preserves
    // parity, so only the odd stream needs a lane shift during reduction.
    let mask31 = _mm256_set1_epi64x(MASK31 as i64);
    let top_mask = _mm256_set_epi64x(0, 0, 0, MASK31 as i64);
    let mut re = [zero; 4];
    let mut ro = [zero; 3];
    for j in 0..4 {
        let high = _mm256_add_epi64(
            _mm256_srli_epi64(e[j + 3], 31),
            _mm256_slli_epi64(_mm256_and_si256(o[j + 3], mask31), 21),
        );
        let low = if j == 3 {
            _mm256_and_si256(e[j], top_mask)
        } else {
            e[j]
        };
        re[j] = _mm256_add_epi64(low, high);
        if j < 3 {
            let next = _mm256_alignr_epi64(e[j + 4], e[j + 3], 1);
            ro[j] = _mm256_add_epi64(
                o[j],
                _mm256_add_epi64(
                    _mm256_srli_epi64(o[j + 3], 31),
                    _mm256_slli_epi64(_mm256_and_si256(next, mask31), 21),
                ),
            );
        }
    }

    // At most 25 products contribute to each coefficient half, so the
    // uncarried sums and the Mersenne fold fit comfortably in u64.
    let mask52 = _mm256_set1_epi64x(MASK52 as i64);
    loop {
        let wrap = _mm256_srli_epi64(re[3], 31);
        let mut prev = zero;
        let mut any = zero;
        for j in 0..3 {
            let ce = _mm256_srli_epi64(re[j], 52);
            let co = _mm256_srli_epi64(ro[j], 52);
            re[j] = _mm256_add_epi64(
                _mm256_and_si256(re[j], mask52),
                _mm256_alignr_epi64(co, prev, 3),
            );
            ro[j] = _mm256_add_epi64(_mm256_and_si256(ro[j], mask52), ce);
            if j == 0 {
                re[j] = _mm256_add_epi64(re[j], wrap);
            }
            prev = co;
            any = _mm256_or_si256(any, _mm256_or_si256(re[j], ro[j]));
        }
        re[3] = _mm256_add_epi64(
            _mm256_and_si256(re[3], top_mask),
            _mm256_alignr_epi64(zero, prev, 3),
        );
        let lower = _mm256_test_epi64_mask(any, _mm256_set1_epi64x(!MASK52 as i64));
        let top = _mm256_test_epi64_mask(re[3], _mm256_set1_epi64x(!MASK31 as i64));
        // Keep the branch in the mask domain; no mask-to-GPR round trip.
        // Inputs are read-only and the assembly touches no memory or stack.
        core::arch::asm!(
            "kortestw {lower}, {top}",
            "jnz {carry}",
            lower = in(kreg) lower as u16,
            top = in(kreg) top as u16,
            carry = label { continue; },
            options(nomem, nostack),
        );
        break;
    }
    let interleave_lo = _mm256_set_epi64x(5, 1, 4, 0);
    let interleave_hi = _mm256_set_epi64x(7, 3, 6, 2);
    let mut out = [zero; 7];
    for j in 0..3 {
        out[2 * j] = _mm256_permutex2var_epi64(re[j], interleave_lo, ro[j]);
        out[2 * j + 1] = _mm256_permutex2var_epi64(re[j], interleave_hi, ro[j]);
    }
    out[6] = re[3];
    out
}
