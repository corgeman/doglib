//! AVX-512 IFMA arithmetic modulo 2^1279 - 1, using 25 radix-2^52 limbs.
//! Even and odd product coefficients are accumulated separately: each IFMA
//! multiplies two register windows, with no scalar broadcasts or inline assembly.

use super::field::Fe1279;
use core::arch::x86_64::*;

const MASK52: u64 = (1u64 << 52) - 1;
const MASK31: u64 = (1u64 << 31) - 1;

#[inline]
pub(crate) fn is_supported() -> bool {
    std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512ifma")
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn load(fe: &Fe1279) -> [__m512i; 4] {
    let p = fe.limb.as_ptr();
    // Fe1279 is 64-byte aligned. The final masked load reads only limb 24;
    // the seven zero lanes also provide padding for all register windows.
    [
        _mm512_load_si512(p.cast()),
        _mm512_load_si512(p.add(8).cast()),
        _mm512_load_si512(p.add(16).cast()),
        _mm512_maskz_loadu_epi64(1, p.add(24).cast()),
    ]
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn store(fe: &mut Fe1279, x: [__m512i; 4]) {
    let p = fe.limb.as_mut_ptr();
    _mm512_store_si512(p.cast(), x[0]);
    _mm512_store_si512(p.add(8).cast(), x[1]);
    _mm512_store_si512(p.add(16).cast(), x[2]);
    _mm512_mask_storeu_epi64(p.add(24).cast(), 1, x[3]);
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn canonicalize(x: &mut [__m512i; 4]) {
    let all = _mm512_and_si512(_mm512_and_si512(x[0], x[1]), x[2]);
    if _mm512_cmpeq_epi64_mask(all, _mm512_set1_epi64(MASK52 as i64)) == 0xff
        && _mm512_cmpeq_epi64_mask(x[3], _mm512_set1_epi64(MASK31 as i64)) & 1 != 0
    {
        *x = [_mm512_setzero_si512(); 4];
    }
}

#[cfg(test)]
#[target_feature(enable = "avx512f,avx512ifma")]
pub unsafe fn single_square_mod(fe: &mut Fe1279) {
    let mut x = square(load(fe));
    canonicalize(&mut x);
    store(fe, x);
}

#[cfg(test)]
#[target_feature(enable = "avx512f,avx512ifma")]
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
/// Caller must ensure AVX512F and AVX512IFMA are supported. Input limbs must
/// fit in 52 bits, with only 31 bits in the final limb.
#[target_feature(enable = "avx512f,avx512ifma")]
pub unsafe fn solve_inner(fe: &mut Fe1279, difficulty: u32) {
    let mut x = load(fe);
    let one = _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, 1);
    for _ in 0..difficulty {
        for _ in 0..1277 {
            x = square(x);
        }
        // The redundant representation p is harmless during squaring, but
        // must become zero before XOR, which is not a field operation.
        canonicalize(&mut x);
        x[0] = _mm512_xor_si512(x[0], one);
    }
    store(fe, x);
}

/// Eight consecutive limbs, zero-padded outside 0..25. All offsets are
/// compile-time constants; each non-aligned window becomes one VALIGNQ.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn window<const I: i32>(x: &[__m512i; 4]) -> __m512i {
    const { assert!(I >= -7 && I <= 24) };
    let zero = _mm512_setzero_si512();
    let lo = if I < 0 { zero } else { x[(I / 8) as usize] };
    let hi = if I < 0 {
        x[0]
    } else if I < 24 {
        x[(I / 8 + 1) as usize]
    } else {
        zero
    };
    match I & 7 {
        0 => lo,
        1 => _mm512_alignr_epi64(hi, lo, 1),
        2 => _mm512_alignr_epi64(hi, lo, 2),
        3 => _mm512_alignr_epi64(hi, lo, 3),
        4 => _mm512_alignr_epi64(hi, lo, 4),
        5 => _mm512_alignr_epi64(hi, lo, 5),
        6 => _mm512_alignr_epi64(hi, lo, 6),
        7 => _mm512_alignr_epi64(hi, lo, 7),
        _ => unreachable!(),
    }
}

macro_rules! products {
    ($x:expr; $(($l:literal, $r:literal)),+ $(,)?) => {{
        let mut lo = _mm512_setzero_si512();
        let mut hi = _mm512_setzero_si512();
        $(
            let a = window::<$l>(&$x);
            let b = window::<$r>(&$x);
            lo = _mm512_madd52lo_epu64(lo, a, b);
            hi = _mm512_madd52hi_epu64(hi, a, b);
        )+
        (lo, hi)
    }};
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn square(x: [__m512i; 4]) -> [__m512i; 4] {
    // For coefficient 2k, pair a[k-t] with a[k+t]; for 2k+1, pair
    // a[k-t] with a[k+t+1]. Padding eliminates all triangular IFMA masks.
    let zero = _mm512_setzero_si512();
    let even = [
        products!(x; (-1, 1), (-2, 2), (-3, 3), (-4, 4), (-5, 5), (-6, 6), (-7, 7)),
        products!(x; (7, 9), (6, 10), (5, 11), (4, 12), (3, 13), (2, 14),
            (1, 15), (0, 16), (-1, 17), (-2, 18), (-3, 19), (-4, 20)),
        products!(x; (15, 17), (14, 18), (13, 19), (12, 20), (11, 21),
            (10, 22), (9, 23), (8, 24)),
        (zero, zero),
    ];
    let odd = [
        products!(x; (0, 1), (-1, 2), (-2, 3), (-3, 4), (-4, 5), (-5, 6), (-6, 7), (-7, 8)),
        products!(x; (8, 9), (7, 10), (6, 11), (5, 12), (4, 13), (3, 14),
            (2, 15), (1, 16), (0, 17), (-1, 18), (-2, 19), (-3, 20)),
        products!(x; (16, 17), (15, 18), (14, 19), (13, 20), (12, 21),
            (11, 22), (10, 23), (9, 24)),
        (zero, zero),
    ];

    let interleave_lo = _mm512_set_epi64(11, 3, 10, 2, 9, 1, 8, 0);
    let interleave_hi = _mm512_set_epi64(15, 7, 14, 6, 13, 5, 12, 4);
    let mut accum = [zero; 8];
    let mut prev = zero;
    for j in 0..4 {
        let el = _mm512_madd52lo_epu64(_mm512_add_epi64(even[j].0, even[j].0), x[j], x[j]);
        let eh = _mm512_madd52hi_epu64(_mm512_add_epi64(even[j].1, even[j].1), x[j], x[j]);
        let ol = _mm512_add_epi64(odd[j].0, odd[j].0);
        let oh = _mm512_add_epi64(odd[j].1, odd[j].1);
        let e = _mm512_add_epi64(el, _mm512_alignr_epi64(oh, prev, 7));
        let o = _mm512_add_epi64(ol, eh);
        accum[2 * j] = _mm512_permutex2var_epi64(e, interleave_lo, o);
        accum[2 * j + 1] = _mm512_permutex2var_epi64(e, interleave_hi, o);
        prev = oh;
    }

    // Fold the uncarried product at bit 1279. Coefficients have at most
    // 25 contributions per half, so all additions fit comfortably in u64.
    let mask31 = _mm512_set1_epi64(MASK31 as i64);
    let top_mask = _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, MASK31 as i64);
    let mut high = [zero; 4];
    let mut prev = zero;
    for j in (0..4).rev() {
        let src = accum[j + 3];
        let up = _mm512_slli_epi64(_mm512_and_si512(src, mask31), 21);
        high[j] = _mm512_add_epi64(_mm512_srli_epi64(src, 31), _mm512_alignr_epi64(prev, up, 1));
        prev = up;
    }
    accum[3] = _mm512_and_si512(accum[3], top_mask);
    let mut out = [zero; 4];
    for j in 0..4 {
        out[j] = _mm512_add_epi64(accum[j], high[j]);
    }

    // Normalize all 25 limbs, including carries caused by the Mersenne wrap.
    // Usually one pass suffices; carry chains at the modulus need more.
    let mask52 = _mm512_set1_epi64(MASK52 as i64);
    loop {
        let c0 = _mm512_srli_epi64(out[0], 52);
        let c1 = _mm512_srli_epi64(out[1], 52);
        let c2 = _mm512_srli_epi64(out[2], 52);
        let wrap = _mm512_srli_epi64(out[3], 31);
        out[0] = _mm512_add_epi64(
            _mm512_add_epi64(_mm512_and_si512(out[0], mask52), _mm512_alignr_epi64(c0, zero, 7)),
            wrap,
        );
        out[1] = _mm512_add_epi64(_mm512_and_si512(out[1], mask52), _mm512_alignr_epi64(c1, c0, 7));
        out[2] = _mm512_add_epi64(_mm512_and_si512(out[2], mask52), _mm512_alignr_epi64(c2, c1, 7));
        out[3] = _mm512_add_epi64(_mm512_and_si512(out[3], top_mask), _mm512_alignr_epi64(zero, c2, 7));
        let lower = _mm512_or_si512(_mm512_or_si512(out[0], out[1]), out[2]);
        if _mm512_test_epi64_mask(lower, _mm512_set1_epi64(!MASK52 as i64)) == 0
            && _mm512_test_epi64_mask(out[3], _mm512_set1_epi64(!MASK31 as i64)) == 0
        {
            break;
        }
    }
    out
}
