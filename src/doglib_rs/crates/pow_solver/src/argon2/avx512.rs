/*
Copyright (c) 2026, NexusXe <nex@nexusxe.com>
Copyright (c) 2018-2019, tevador <tevador@gmail.com>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* Original code from the Argon2 reference source package used under CC0:
 * https://github.com/P-H-C/phc-winner-argon2
 * Copyright 2015 Daniel Dinu, Dmitry Khovratovich,
 * Jean-Philippe Aumasson, and Samuel Neves.
 */

use super::Challenge;

#[cfg(target_arch = "x86_64")]
mod imp {
    use std::sync::OnceLock;

    use blake2::digest::{Update, VariableOutput};
    use blake2::{Blake2b512, Blake2bVar, Digest};
    use core::arch::x86_64::*;

    use super::super::{
        build_prefix, proof_shape, Challenge, ARGON2I_REFS, ARGON2_BLOCKS,
        ARGON2_SEGMENT_LENGTH, COUNTER_LEN, HASH_LEN, SUBPROOF_LEN,
    };

    const ARGON2_QWORDS: usize = 128;
    const ARGON2_BLOCK_BYTES: usize = 1024;

    #[repr(C, align(64))]
    struct Block([u64; ARGON2_QWORDS]);

    pub(super) fn available() -> bool {
        std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("vaes")
    }

    fn allocate_arena() -> Result<Vec<Block>, String> {
        let mut arena = Vec::new();
        arena
            .try_reserve_exact(ARGON2_BLOCKS)
            .map_err(|_| "failed to allocate Argon2 worker arena".to_string())?;
        arena.resize_with(ARGON2_BLOCKS, || Block([0; ARGON2_QWORDS]));
        Ok(arena)
    }

    /// Views the block's sole contiguous qword field as bytes. This backend is
    /// x86-64-only (therefore little-endian), and `Block` is aligned beyond the
    /// byte view's requirement.
    fn block_bytes(block: &Block) -> &[u8; ARGON2_BLOCK_BYTES] {
        unsafe { &*block.0.as_ptr().cast::<[u8; ARGON2_BLOCK_BYTES]>() }
    }

    /// Mutable counterpart to `block_bytes`; the exclusive block borrow keeps
    /// the casted byte view unaliased for its lifetime.
    fn block_bytes_mut(block: &mut Block) -> &mut [u8; ARGON2_BLOCK_BYTES] {
        unsafe { &mut *block.0.as_mut_ptr().cast::<[u8; ARGON2_BLOCK_BYTES]>() }
    }

    fn blake2b512(parts: &[&[u8]]) -> [u8; 64] {
        let mut hasher = Blake2b512::new();
        for part in parts {
            Digest::update(&mut hasher, part);
        }
        hasher.finalize().into()
    }

    fn blake2b_var(parts: &[&[u8]], output: &mut [u8]) {
        let mut hasher = Blake2bVar::new(output.len()).expect("valid BLAKE2b output length");
        for part in parts {
            Update::update(&mut hasher, part);
        }
        hasher
            .finalize_variable(output)
            .expect("output length fixed at construction");
    }

    fn make_h0(prefix: &[u8; SUBPROOF_LEN], counter: u64) -> [u8; 64] {
        blake2b512(&[
            &1u32.to_le_bytes(),
            &(HASH_LEN as u32).to_le_bytes(),
            &(ARGON2_BLOCKS as u32).to_le_bytes(),
            &1u32.to_le_bytes(),
            &0x13u32.to_le_bytes(),
            &2u32.to_le_bytes(),
            &(SUBPROOF_LEN as u32).to_le_bytes(),
            prefix,
            &((SUBPROOF_LEN + COUNTER_LEN) as u32).to_le_bytes(),
            prefix,
            &counter.to_be_bytes(),
            &0u32.to_le_bytes(),
            &0u32.to_le_bytes(),
        ])
    }

    /// RFC 9106 variable-length hash H'. BLAKE2b's requested output length is
    /// part of its parameter block, so short outputs must use `Blake2bVar`
    /// rather than truncating BLAKE2b-512.
    fn hprime(input: &[u8], output: &mut [u8]) {
        let output_len = (output.len() as u32).to_le_bytes();
        if output.len() <= 64 {
            blake2b_var(&[&output_len, input], output);
            return;
        }

        let rounds = output.len().div_ceil(32) - 2;
        let mut value = blake2b512(&[&output_len, input]);
        output[..32].copy_from_slice(&value[..32]);
        for round in 1..rounds {
            value = blake2b512(&[&value]);
            output[round * 32..round * 32 + 32].copy_from_slice(&value[..32]);
        }
        blake2b_var(&[&value], &mut output[rounds * 32..]);
    }

    fn initialize_block(block: &mut Block, h0: &[u8; 64], index: u32) {
        let mut input = [0; 72];
        input[..64].copy_from_slice(h0);
        input[64..68].copy_from_slice(&index.to_le_bytes());
        hprime(&input, block_bytes_mut(block));
    }

    fn ref_index_alpha(slice: u32, index: u32, pseudo_rand: u32) -> usize {
        let reference_area_size = slice * ARGON2_SEGMENT_LENGTH as u32 + index - 1;
        let mut relative = pseudo_rand as u64;
        relative = relative.wrapping_mul(relative) >> 32;
        relative = reference_area_size as u64
            - 1
            - ((reference_area_size as u64).wrapping_mul(relative) >> 32);
        relative as usize
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn pack_lower(v0: __m512i, v1: __m512i) -> __m512i {
        _mm512_inserti64x4(
            _mm512_castsi256_si512(_mm512_castsi512_si256(v0)),
            _mm512_castsi512_si256(v1),
            1,
        )
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn pack_upper(v0: __m512i, v1: __m512i) -> __m512i {
        _mm512_inserti64x4(
            _mm512_castsi256_si512(_mm512_extracti64x4_epi64(v0, 1)),
            _mm512_extracti64x4_epi64(v1, 1),
            1,
        )
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn g1(a: &mut __m512i, b: &mut __m512i, c: &mut __m512i, d: &mut __m512i) {
        let mut product = _mm512_mul_epu32(*a, *b);
        product = _mm512_add_epi64(product, product);
        *a = _mm512_add_epi64(*a, _mm512_add_epi64(*b, product));
        *d = _mm512_ror_epi64::<32>(_mm512_xor_si512(*d, *a));

        product = _mm512_mul_epu32(*c, *d);
        product = _mm512_add_epi64(product, product);
        *c = _mm512_add_epi64(*c, _mm512_add_epi64(*d, product));
        *b = _mm512_ror_epi64::<24>(_mm512_xor_si512(*b, *c));
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn g2(a: &mut __m512i, b: &mut __m512i, c: &mut __m512i, d: &mut __m512i) {
        let mut product = _mm512_mul_epu32(*a, *b);
        product = _mm512_add_epi64(product, product);
        *a = _mm512_add_epi64(*a, _mm512_add_epi64(*b, product));
        *d = _mm512_ror_epi64::<16>(_mm512_xor_si512(*d, *a));

        product = _mm512_mul_epu32(*c, *d);
        product = _mm512_add_epi64(product, product);
        *c = _mm512_add_epi64(*c, _mm512_add_epi64(*d, product));
        *b = _mm512_ror_epi64::<63>(_mm512_xor_si512(*b, *c));
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn round_1(a: &mut __m512i, b: &mut __m512i, c: &mut __m512i, d: &mut __m512i) {
        g1(a, b, c, d);
        g2(a, b, c, d);
        *b = _mm512_permutex_epi64::<0x39>(*b);
        *c = _mm512_permutex_epi64::<0x4e>(*c);
        *d = _mm512_permutex_epi64::<0x93>(*d);
        g1(a, b, c, d);
        g2(a, b, c, d);
        *b = _mm512_permutex_epi64::<0x93>(*b);
        *c = _mm512_permutex_epi64::<0x4e>(*c);
        *d = _mm512_permutex_epi64::<0x39>(*d);
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn round_2(a: &mut __m512i, b: &mut __m512i, c: &mut __m512i, d: &mut __m512i) {
        g1(a, b, c, d);
        g2(a, b, c, d);
        let index_b = _mm512_set_epi64(2, 7, 0, 5, 6, 3, 4, 1);
        let index_c = _mm512_set_epi64(3, 2, 1, 0, 7, 6, 5, 4);
        let index_d = _mm512_set_epi64(6, 3, 4, 1, 2, 7, 0, 5);
        *b = _mm512_permutexvar_epi64(index_b, *b);
        *c = _mm512_permutexvar_epi64(index_c, *c);
        *d = _mm512_permutexvar_epi64(index_d, *d);
        g1(a, b, c, d);
        g2(a, b, c, d);
        *b = _mm512_permutexvar_epi64(index_d, *b);
        *c = _mm512_permutexvar_epi64(index_c, *c);
        *d = _mm512_permutexvar_epi64(index_b, *d);
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn load_state(block: &Block) -> [__m512i; 16] {
        let pointer = block.0.as_ptr().cast::<__m512i>();
        std::array::from_fn(|i| _mm512_load_si512(pointer.add(i)))
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn fill_block(state: &mut [__m512i; 16], reference: &Block, output: &mut Block) {
        let reference_pointer = reference.0.as_ptr().cast::<__m512i>();
        let mut block_xy = [_mm512_setzero_si512(); 16];
        for i in 0..16 {
            state[i] = _mm512_xor_si512(state[i], _mm512_load_si512(reference_pointer.add(i)));
            block_xy[i] = state[i];
        }

        for i in 0..4 {
            let mut a = pack_lower(state[4 * i], state[4 * i + 2]);
            let mut b = pack_upper(state[4 * i], state[4 * i + 2]);
            let mut c = pack_lower(state[4 * i + 1], state[4 * i + 3]);
            let mut d = pack_upper(state[4 * i + 1], state[4 * i + 3]);
            round_1(&mut a, &mut b, &mut c, &mut d);
            state[4 * i] = pack_lower(a, b);
            state[4 * i + 2] = pack_upper(a, b);
            state[4 * i + 1] = pack_lower(c, d);
            state[4 * i + 3] = pack_upper(c, d);
        }

        for j in 0..2 {
            let mut a0 = pack_lower(state[j], state[j + 2]);
            let mut b0 = pack_lower(state[j + 4], state[j + 6]);
            let mut c0 = pack_lower(state[j + 8], state[j + 10]);
            let mut d0 = pack_lower(state[j + 12], state[j + 14]);
            let mut a1 = pack_upper(state[j], state[j + 2]);
            let mut b1 = pack_upper(state[j + 4], state[j + 6]);
            let mut c1 = pack_upper(state[j + 8], state[j + 10]);
            let mut d1 = pack_upper(state[j + 12], state[j + 14]);
            round_2(&mut a0, &mut b0, &mut c0, &mut d0);
            round_2(&mut a1, &mut b1, &mut c1, &mut d1);
            state[j] = pack_lower(a0, a1);
            state[j + 2] = pack_upper(a0, a1);
            state[j + 4] = pack_lower(b0, b1);
            state[j + 6] = pack_upper(b0, b1);
            state[j + 8] = pack_lower(c0, c1);
            state[j + 10] = pack_upper(c0, c1);
            state[j + 12] = pack_lower(d0, d1);
            state[j + 14] = pack_upper(d0, d1);
        }

        let output_pointer = output.0.as_mut_ptr().cast::<__m512i>();
        for i in 0..16 {
            state[i] = _mm512_xor_si512(state[i], block_xy[i]);
            _mm512_store_si512(output_pointer.add(i), state[i]);
        }
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn fill_memory(arena: &mut [Block]) {
        let mut state = load_state(&arena[1]);
        for j in 2..ARGON2_BLOCKS {
            let slice = (j / ARGON2_SEGMENT_LENGTH) as u32;
            let index = (j % ARGON2_SEGMENT_LENGTH) as u32;
            let reference_index = if j < 2 * ARGON2_SEGMENT_LENGTH {
                ARGON2I_REFS[j] as usize
            } else {
                ref_index_alpha(slice, index, arena[j - 1].0[0] as u32)
            };
            debug_assert!(reference_index < j);
            let (previous, remaining) = arena.split_at_mut(j);
            fill_block(&mut state, &previous[reference_index], &mut remaining[0]);
        }
    }

    fn hash(arena: &mut [Block], prefix: &[u8; SUBPROOF_LEN], counter: u64) -> [u8; HASH_LEN] {
        debug_assert!(available());
        let h0 = make_h0(prefix, counter);
        initialize_block(&mut arena[0], &h0, 0);
        initialize_block(&mut arena[1], &h0, 1);
        // Safety: `available` checks AVX-512F plus OS support before any caller
        // reaches this boundary. All SIMD helpers stay below this call.
        unsafe { fill_memory(arena) };
        let mut digest = [0; HASH_LEN];
        hprime(block_bytes(&arena[ARGON2_BLOCKS - 1]), &mut digest);
        digest
    }

    fn leading_zero_bits(digest: &[u8; HASH_LEN]) -> u32 {
        let mut bits = 0;
        for byte in digest {
            if *byte == 0 {
                bits += 8;
            } else {
                return bits + byte.leading_zeros();
            }
        }
        bits
    }

    pub(super) fn solve(challenge: &Challenge, workers: i64) -> Result<String, String> {
        if !available() {
            return Err("AVX-512 backend unavailable".to_string());
        }
        let worker_count = if workers <= 0 {
            std::thread::available_parallelism().map_or(1, usize::from)
        } else {
            workers as usize
        };
        let mut arenas = Vec::new();
        arenas
            .try_reserve_exact(worker_count)
            .map_err(|_| "failed to allocate Argon2 worker arena".to_string())?;
        for _ in 0..worker_count {
            arenas.push(allocate_arena()?);
        }

        let (proof_count, proof_difficulty) = proof_shape(challenge.difficulty);
        let mut chain = [0; HASH_LEN];
        let mut counters = Vec::with_capacity(proof_count as usize);
        for index in 0..proof_count {
            let prefix = build_prefix(&challenge.password, index, &chain);
            let winner = OnceLock::new();
            std::thread::scope(|scope| {
                for (worker, arena) in arenas.iter_mut().enumerate() {
                    let winner = &winner;
                    scope.spawn(move || {
                        let mut counter = worker as u64;
                        loop {
                            if winner.get().is_some() {
                                return;
                            }
                            let digest = hash(arena, &prefix, counter);
                            if leading_zero_bits(&digest) >= proof_difficulty {
                                let _ = winner.set((counter, digest));
                                return;
                            }
                            let Some(next) = counter.checked_add(worker_count as u64) else {
                                return;
                            };
                            counter = next;
                        }
                    });
                }
            });
            let (counter, digest) = winner
                .get()
                .copied()
                .ok_or_else(|| "counter space exhausted".to_string())?;
            counters.push(format!("{counter:x}"));
            chain = digest;
        }
        Ok(counters.join("."))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fixed_hash_matches_argon2_cffi() {
            if !available() {
                return;
            }
            let mut prefix = [0; SUBPROOF_LEN];
            for (value, byte) in prefix[..16].iter_mut().zip(0u8..16) {
                *value = byte;
            }
            let mut arena = allocate_arena().unwrap();
            assert_eq!(
                hash(&mut arena, &prefix, 0),
                [
                    0x0a, 0x28, 0xe0, 0xff, 0xd4, 0x6f, 0xd1, 0x13,
                    0xcd, 0x69, 0x2a, 0xc2, 0x48, 0x44, 0xe8, 0x29,
                    0x9f, 0xae, 0xbe, 0x44, 0xe8, 0x39, 0xb1, 0xdf,
                    0x5c, 0x11, 0x23, 0x6d, 0x4e, 0x51, 0x2b, 0x36,
                ]
            );
        }

        #[test]
        fn solves_fixed_difficulty_one_challenge() {
            if !available() {
                return;
            }
            let challenge = Challenge {
                difficulty: 1,
                password: std::array::from_fn(|i| i as u8),
            };
            assert_eq!(solve(&challenge, 1).unwrap(), "0");
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub(super) fn available() -> bool {
    imp::available()
}

#[cfg(target_arch = "x86_64")]
pub(super) fn solve(challenge: &Challenge, workers: i64) -> Result<String, String> {
    imp::solve(challenge, workers)
}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn available() -> bool {
    false
}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn solve(_challenge: &Challenge, _workers: i64) -> Result<String, String> {
    Err("AVX-512 backend unavailable".to_string())
}
