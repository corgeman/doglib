/// 1279-bit field element mod (2^1279 - 1) stored as 25 x 52-bit limbs.
///
/// Limb 0 is the least significant. Limb 24 uses only 31 bits (1279 - 24*52 = 31).

const LIMBS: usize = 25;
const PROD_LIMBS: usize = LIMBS * 2;
const MASK52: u64 = (1u64 << 52) - 1;
const MASK31: u64 = (1u64 << 31) - 1;

#[derive(Clone, Copy)]
#[repr(align(64))]
pub struct Fe1279 {
    pub limb: [u64; LIMBS],
}

impl Fe1279 {
    pub const ZERO: Self = Self { limb: [0; LIMBS] };

    /// Load from big-endian bytes.
    pub fn from_be_bytes(buf: &[u8]) -> Self {
        let mut out = Self::ZERO;
        let mut acc: u128 = 0;
        let mut acc_bits: u32 = 0;
        let mut li = 0;
        for i in (0..buf.len()).rev() {
            acc |= (buf[i] as u128) << acc_bits;
            acc_bits += 8;
            while acc_bits >= 52 {
                out.limb[li] = (acc as u64) & MASK52;
                acc >>= 52;
                acc_bits -= 52;
                li += 1;
            }
        }
        if acc_bits > 0 && li < LIMBS {
            out.limb[li] = acc as u64;
        }
        out.limb[LIMBS - 1] &= MASK31;
        out
    }

    /// Write to big-endian bytes, returning the number of bytes written (no leading zeros).
    pub fn to_be_bytes(&self, out: &mut [u8; 168]) -> usize {
        let mut tmp = [0u8; 168];
        let mut acc: u128 = 0;
        let mut acc_bits: u32 = 0;
        let mut n = 0usize;

        for i in 0..LIMBS {
            acc |= (self.limb[i] as u128) << acc_bits;
            acc_bits += 52;
            while acc_bits >= 8 {
                tmp[n] = (acc & 0xFF) as u8;
                acc >>= 8;
                acc_bits -= 8;
                n += 1;
            }
        }
        if acc_bits > 0 {
            tmp[n] = acc as u8;
            n += 1;
        }

        while n > 0 && tmp[n - 1] == 0 {
            n -= 1;
        }
        for i in 0..n {
            out[i] = tmp[n - 1 - i];
        }
        n
    }

    /// x ^= 1 (flip LSB)
    #[inline(always)]
    pub fn xor_one(&mut self) {
        self.limb[0] ^= 1;
    }

    /// Schoolbook squaring mod (2^1279 - 1) using scalar u128 arithmetic.
    pub fn square_mod(&mut self) {
        let a = self.limb;

        // Accumulate 50-limb product in u128 to avoid overflow
        let mut prod = [0u128; PROD_LIMBS];

        for i in 0..LIMBS {
            prod[2 * i] += (a[i] as u128) * (a[i] as u128);
            for j in (i + 1)..LIMBS {
                let cross = (a[i] as u128) * (a[j] as u128);
                prod[i + j] += cross << 1; // 2 * cross
            }
        }

        // Carry-propagate into 52-bit limbs
        let mut full = [0u64; PROD_LIMBS + 1];
        let mut carry: u128 = 0;
        for i in 0..PROD_LIMBS {
            let total = prod[i] + carry;
            full[i] = (total as u64) & MASK52;
            carry = total >> 52;
        }
        full[PROD_LIMBS] = carry as u64;

        // Mersenne reduction: result = (full & (2^1279-1)) + (full >> 1279)
        // Bit 1279 sits at bit 31 of limb 24.
        self.reduce_from_full(&full);
    }

    /// Reduce a full 50-limb product modulo 2^1279 - 1.
    fn reduce_from_full(&mut self, full: &[u64; PROD_LIMBS + 1]) {
        // low = full[0..25], with limb 24 masked to 31 bits
        // high = full >> 1279 (shift by 24 limbs + 31 bits)
        let mut high = [0u64; LIMBS + 1];
        for i in 0..=LIMBS {
            let src = i + 24;
            let lo = if src < PROD_LIMBS + 1 { full[src] >> 31 } else { 0 };
            let hi = if src + 1 < PROD_LIMBS + 1 {
                (full[src + 1] & MASK31) << 21
            } else {
                0
            };
            high[i] = lo | hi;
        }

        // result = low + high
        let mut carry: u128 = 0;
        for i in 0..LIMBS {
            let low_i = if i < 24 {
                full[i] as u128
            } else {
                (full[24] & MASK31) as u128
            };
            let sum = low_i + (high[i] as u128) + carry;
            self.limb[i] = (sum as u64) & MASK52;
            carry = sum >> 52;
        }
        carry += high[LIMBS] as u128;

        // Any carry or overflow from limb 24 exceeding 31 bits wraps via Mersenne property.
        // 2^(25*52) = 2^1300 ≡ 2^21 (mod 2^1279-1)
        // Bits above 31 in limb 24: val * 2^1279 ≡ val (mod 2^1279-1)
        loop {
            let overflow = (self.limb[LIMBS - 1] >> 31) + ((carry as u64) << 21);
            self.limb[LIMBS - 1] &= MASK31;
            if overflow == 0 {
                break;
            }
            let mut c = overflow as u128;
            for i in 0..LIMBS {
                if c == 0 {
                    break;
                }
                let sum = (self.limb[i] as u128) + c;
                self.limb[i] = (sum as u64) & MASK52;
                c = sum >> 52;
            }
            carry = c;
        }

        if self.is_modulus() {
            *self = Self::ZERO;
        }
    }

    fn is_modulus(&self) -> bool {
        if self.limb[LIMBS - 1] != MASK31 {
            return false;
        }
        for i in 0..(LIMBS - 1) {
            if self.limb[i] != MASK52 {
                return false;
            }
        }
        true
    }

    /// 1277 squarings (one "sqrt" step of the Sloth VDF).
    pub fn sqrt_step(&mut self) {
        for _ in 0..1277 {
            self.square_mod();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bytes() {
        let input = [
            0x1F, 0xE7, 0xCF, 0x8A, 0xE2, 0xF7, 0xD8, 0x33, 0xDB, 0x7C, 0xDF, 0x7B,
            0x72, 0x97, 0x74, 0x9C,
        ];
        let fe = Fe1279::from_be_bytes(&input);
        let mut out = [0u8; 168];
        let n = fe.to_be_bytes(&mut out);
        assert_eq!(&out[..n], &input);
    }

    #[test]
    fn xor_one_toggles_lsb() {
        let mut fe = Fe1279::from_be_bytes(&[0x00]);
        fe.xor_one();
        assert_eq!(fe.limb[0], 1);
        fe.xor_one();
        assert_eq!(fe.limb[0], 0);
    }

    #[test]
    fn scalar_solve_difficulty_1() {
        use crate::solver;
        let result =
            solver::solve_with("scalar", "s.AAAAAQ==.H+fPiuL32DPbfN97cpd0nA==").unwrap();
        let expected = "s.SehdFNCoMtQI4d9JBXsmzWdYk77jtb36Io5acLmjB6l/Vr1VUUsegi3CNbUf7lgUI5kGuxgdleSh+poE/BCGoAoaTNGVBC14jl+W0D7wg8R2IPDCUSTueG0JNCtJL8OeNPiReJ+CBFcqcR0Ntc9Qakzm8sZaBjGld1Rh3FK6gresUqjpnxGS4SgIg/lp/iZ+2EetM94ewJHsXghGaWQYkg==";
        assert_eq!(result, expected);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn avx512_divergence_step() {
        if !std::arch::is_x86_feature_detected!("avx512ifma") {
            eprintln!("skipping: CPU lacks AVX512 IFMA");
            return;
        }
        use crate::field_avx512;

        let input = [
            0x1F, 0xE7, 0xCF, 0x8A, 0xE2, 0xF7, 0xD8, 0x33, 0xDB, 0x7C, 0xDF, 0x7B,
            0x72, 0x97, 0x74, 0x9C,
        ];
        let fe = Fe1279::from_be_bytes(&input);
        let result = unsafe { field_avx512::debug_compare_squarings(&fe, 1277) };
        assert_eq!(result, None, "diverged at step {:?}", result);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn avx512_single_squaring_matches_scalar() {
        if !std::arch::is_x86_feature_detected!("avx512ifma") {
            eprintln!("skipping: CPU lacks AVX512 IFMA");
            return;
        }
        use crate::field_avx512;

        let input = [
            0x1F, 0xE7, 0xCF, 0x8A, 0xE2, 0xF7, 0xD8, 0x33, 0xDB, 0x7C, 0xDF, 0x7B,
            0x72, 0x97, 0x74, 0x9C,
        ];

        // Scalar
        let mut scalar = Fe1279::from_be_bytes(&input);
        scalar.square_mod();

        // AVX512 (one squaring via solve_inner with modified approach)
        let mut avx = Fe1279::from_be_bytes(&input);
        unsafe { field_avx512::single_square_mod(&mut avx) };

        for i in 0..LIMBS {
            assert_eq!(
                scalar.limb[i], avx.limb[i],
                "limb {} differs: scalar={:#x} avx={:#x}",
                i, scalar.limb[i], avx.limb[i]
            );
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn avx512_solve_difficulty_1() {
        if !std::arch::is_x86_feature_detected!("avx512ifma") {
            eprintln!("skipping: CPU lacks AVX512 IFMA");
            return;
        }
        use crate::solver;
        let result =
            solver::solve_with("avx512", "s.AAAAAQ==.H+fPiuL32DPbfN97cpd0nA==").unwrap();
        let expected = "s.SehdFNCoMtQI4d9JBXsmzWdYk77jtb36Io5acLmjB6l/Vr1VUUsegi3CNbUf7lgUI5kGuxgdleSh+poE/BCGoAoaTNGVBC14jl+W0D7wg8R2IPDCUSTueG0JNCtJL8OeNPiReJ+CBFcqcR0Ntc9Qakzm8sZaBjGld1Rh3FK6gresUqjpnxGS4SgIg/lp/iZ+2EetM94ewJHsXghGaWQYkg==";
        assert_eq!(result, expected);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn avx512_solve_difficulty_50() {
        if !std::arch::is_x86_feature_detected!("avx512ifma") {
            eprintln!("skipping: CPU lacks AVX512 IFMA");
            return;
        }
        use crate::solver;
        let result =
            solver::solve_with("avx512", "s.AAAAMg==.H+fPiuL32DPbfN97cpd0nA==").unwrap();
        let expected = "s.O5X5tBMcDT3O2E/32edB/FqCuws5LuvMKGGAkqVc9Wak/gJmwkUpUvYWOlr9x+tsccb6/KcNCQTym1Jzclv+aXE49pu5RkukYgijK8gbuuQrfp+YIJ6OFHId2tCIAdV/QYFIrhUy1pVUZ6mGCCCRjGqMVSo6QGDAS59tKKbnGjdZYRLSku30L9GWpSx9Sdjas/PzTxOsN6rjlCBE/qgGHg==";
        assert_eq!(result, expected);
    }

    #[test]
    fn scalar_solve_difficulty_50() {
        use crate::solver;
        let result =
            solver::solve_with("scalar", "s.AAAAMg==.H+fPiuL32DPbfN97cpd0nA==").unwrap();
        let expected = "s.O5X5tBMcDT3O2E/32edB/FqCuws5LuvMKGGAkqVc9Wak/gJmwkUpUvYWOlr9x+tsccb6/KcNCQTym1Jzclv+aXE49pu5RkukYgijK8gbuuQrfp+YIJ6OFHId2tCIAdV/QYFIrhUy1pVUZ6mGCCCRjGqMVSo6QGDAS59tKKbnGjdZYRLSku30L9GWpSx9Sdjas/PzTxOsN6rjlCBE/qgGHg==";
        assert_eq!(result, expected);
    }
}
