// Argon2id proof-of-work search kernel for the bbb `a2id.v2` format.
//
// Device-only port of research/argon_pow/custom_cuda.cu.  Differences from the
// reference (per the doglib_rs design):
//   * No `__constant__` symbols — params arrive as kernel arguments and the
//     argon2i reference table arrives as a global buffer (`i_refs`).
//   * H0 is computed in full on-device per attempt (the reference hoisted the
//     first BLAKE2b block to the host; that saved <0.03% and is dropped so the
//     host needs no BLAKE2b implementation).
//   * Results land in three plain buffers (state/counter/digest) instead of a
//     struct, which keeps the cudarc launch side simple.
//   * The BLAKE2b sigma/IV tables are file-scope `__device__ const`.
//
// One warp computes one Argon2 hash (4 warps/block).  The 1 KiB working block is
// register-resident — each lane holds 4 qwords (block[idx*32+lane]) and lanes
// exchange data with warp shuffles (hashcat/Mosnáček argon2_hash_block), so all
// 32 lanes stay active and there's no shared-memory staging.  Each lane reads
// back only the global qwords it wrote itself, so the fill loop needs no
// barrier; the two per-hash fences cover lane 0's initial/final-block handoff.
//
// Fixed parameters: m=4096 KiB, t=1, p=1, type=id, version=0x13, 32-byte tag.

#include <cstdint>

#define DEV __device__

namespace {

constexpr uint32_t PASSWORD_LEN = 16;
constexpr uint32_t HASH_LEN = 32;
constexpr uint32_t COUNTER_LEN = 8;
constexpr uint32_t SUBPROOF_LEN = PASSWORD_LEN + 4 + HASH_LEN;  // 52
constexpr uint32_t SALT_LEN = SUBPROOF_LEN + COUNTER_LEN;       // 60

constexpr uint32_t ARGON2_BLOCK_BYTES = 1024;
constexpr uint32_t ARGON2_QWORDS = 128;
constexpr uint32_t ARGON2_BLOCKS = 4096;
constexpr uint32_t ARGON2_SEGMENT_LENGTH = 1024;
constexpr uint32_t ARGON2_PASSES = 1;
constexpr uint32_t ARGON2_PARALLELISM = 1;
constexpr uint32_t ARGON2_TYPE_ID = 2;
constexpr uint32_t ARGON2_VERSION = 0x13;
constexpr uint32_t ARGON2_MEMORY_KIB = 4096;
constexpr uint32_t WARP_SIZE = 32;
constexpr uint32_t WARPS_PER_BLOCK = 4;
// Launch with WARP_SIZE * WARPS_PER_BLOCK = 128 threads/block (see argon2.rs).

__device__ const uint64_t BLAKE2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

__device__ const uint8_t BLAKE2B_SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

DEV inline uint64_t rotr64(uint64_t x, uint32_t n) {
    return (x >> n) | (x << (64U - n));
}

DEV inline uint64_t load_le64(const uint8_t* src) {
    uint64_t v = 0;
    for (uint32_t i = 0; i < 8; ++i) v |= static_cast<uint64_t>(src[i]) << (8U * i);
    return v;
}

DEV inline void store_le32(uint8_t* dst, uint32_t value) {
    dst[0] = static_cast<uint8_t>(value);
    dst[1] = static_cast<uint8_t>(value >> 8);
    dst[2] = static_cast<uint8_t>(value >> 16);
    dst[3] = static_cast<uint8_t>(value >> 24);
}

DEV inline void store_le64(uint8_t* dst, uint64_t value) {
    for (uint32_t i = 0; i < 8; ++i) dst[i] = static_cast<uint8_t>(value >> (8U * i));
}

DEV inline void store_be64(uint8_t* dst, uint64_t value) {
    dst[0] = static_cast<uint8_t>(value >> 56);
    dst[1] = static_cast<uint8_t>(value >> 48);
    dst[2] = static_cast<uint8_t>(value >> 40);
    dst[3] = static_cast<uint8_t>(value >> 32);
    dst[4] = static_cast<uint8_t>(value >> 24);
    dst[5] = static_cast<uint8_t>(value >> 16);
    dst[6] = static_cast<uint8_t>(value >> 8);
    dst[7] = static_cast<uint8_t>(value);
}

DEV inline void copy_bytes(uint8_t* dst, const uint8_t* src, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) dst[i] = src[i];
}

DEV inline void zero_bytes(uint8_t* dst, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) dst[i] = 0;
}

DEV unsigned leading_zero_bits_raw(const uint8_t* digest) {
    unsigned count = 0;
    for (uint32_t i = 0; i < HASH_LEN; ++i) {
        uint8_t byte = digest[i];
        if (byte == 0) {
            count += 8;
            continue;
        }
        for (int bit = 7; bit >= 0; --bit) {
            if ((byte & (1U << bit)) != 0) return count;
            ++count;
        }
        return count;
    }
    return count;
}

DEV inline void blake2b_g(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d,
                          uint64_t x, uint64_t y) {
    a = a + b + x;
    d = rotr64(d ^ a, 32);
    c = c + d;
    b = rotr64(b ^ c, 24);
    a = a + b + y;
    d = rotr64(d ^ a, 16);
    c = c + d;
    b = rotr64(b ^ c, 63);
}

DEV void blake2b_compress(uint64_t h[8], const uint8_t block[128], uint64_t t, bool last) {
    uint64_t m[16];
    uint64_t v[16];

    for (uint32_t i = 0; i < 16; ++i) m[i] = load_le64(block + 8U * i);
    for (uint32_t i = 0; i < 8; ++i) {
        v[i] = h[i];
        v[i + 8] = BLAKE2B_IV[i];
    }
    v[12] ^= t;
    if (last) v[14] = ~v[14];

    for (uint32_t r = 0; r < 12; ++r) {
        const uint8_t* s = BLAKE2B_SIGMA[r];
        blake2b_g(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
        blake2b_g(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
        blake2b_g(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
        blake2b_g(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
        blake2b_g(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
        blake2b_g(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        blake2b_g(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
        blake2b_g(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
    }

    for (uint32_t i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

DEV void blake2b_hash(uint8_t* out, uint32_t outlen, const uint8_t* input, uint32_t input_len) {
    uint64_t h[8];
    uint8_t block[128];
    uint32_t offset = 0;
    uint64_t total = 0;

    for (uint32_t i = 0; i < 8; ++i) h[i] = BLAKE2B_IV[i];
    h[0] ^= 0x01010000U | outlen;

    while (input_len - offset > 128) {
        for (uint32_t i = 0; i < 128; ++i) block[i] = input[offset + i];
        total += 128;
        blake2b_compress(h, block, total, false);
        offset += 128;
    }

    uint32_t remaining = input_len - offset;
    zero_bytes(block, 128);
    for (uint32_t i = 0; i < remaining; ++i) block[i] = input[offset + i];
    total += remaining;
    blake2b_compress(h, block, total, true);

    uint8_t full[64];
    for (uint32_t i = 0; i < 8; ++i) store_le64(full + 8U * i, h[i]);
    for (uint32_t i = 0; i < outlen; ++i) out[i] = full[i];
}

// H'(1024) expanding h0 into one 1024-byte Argon2 block (block_index 0 or 1).
DEV void hprime_1024_initial_block(uint64_t* block, const uint8_t h0[64], uint32_t block_index) {
    uint8_t msg[76];
    uint8_t out_buffer[64];
    uint32_t word = 0;

    store_le32(msg, ARGON2_BLOCK_BYTES);
    copy_bytes(msg + 4, h0, 64);
    store_le32(msg + 68, block_index);
    store_le32(msg + 72, 0);

    blake2b_hash(out_buffer, 64, msg, sizeof(msg));
    for (uint32_t i = 0; i < 4; ++i) block[word++] = load_le64(out_buffer + 8U * i);

    for (uint32_t round = 0; round < 29; ++round) {
        blake2b_hash(out_buffer, 64, out_buffer, 64);
        for (uint32_t i = 0; i < 4; ++i) block[word++] = load_le64(out_buffer + 8U * i);
    }

    blake2b_hash(out_buffer, 64, out_buffer, 64);
    for (uint32_t i = 0; i < 8; ++i) block[word++] = load_le64(out_buffer + 8U * i);
}

// H'(32) reducing the final 1024-byte block into the 32-byte tag.
DEV void hprime_32_from_1024_block(uint8_t digest[HASH_LEN], const uint64_t* block_words) {
    uint64_t h[8];
    uint8_t block[128];
    const uint8_t* src = reinterpret_cast<const uint8_t*>(block_words);
    uint32_t src_off = 0;
    uint64_t total = 0;

    for (uint32_t i = 0; i < 8; ++i) h[i] = BLAKE2B_IV[i];
    h[0] ^= 0x01010000U | HASH_LEN;

    store_le32(block, HASH_LEN);
    for (uint32_t i = 0; i < 124; ++i) block[4 + i] = src[src_off++];
    total += 128;
    blake2b_compress(h, block, total, false);

    while (ARGON2_BLOCK_BYTES - src_off > 128) {
        for (uint32_t i = 0; i < 128; ++i) block[i] = src[src_off + i];
        src_off += 128;
        total += 128;
        blake2b_compress(h, block, total, false);
    }

    uint32_t remaining = ARGON2_BLOCK_BYTES - src_off;
    zero_bytes(block, 128);
    for (uint32_t i = 0; i < remaining; ++i) block[i] = src[src_off + i];
    total += remaining;
    blake2b_compress(h, block, total, true);

    uint8_t full[64];
    for (uint32_t i = 0; i < 8; ++i) store_le64(full + 8U * i, h[i]);
    for (uint32_t i = 0; i < HASH_LEN; ++i) digest[i] = full[i];
}

DEV inline uint64_t blamka(uint64_t x, uint64_t y) {
    const uint64_t mask = 0xffffffffULL;
    return x + y + 2ULL * (x & mask) * (y & mask);
}

DEV inline void argon2_g(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) {
    a = blamka(a, b);
    d = rotr64(d ^ a, 32);
    c = blamka(c, d);
    b = rotr64(b ^ c, 24);
    a = blamka(a, b);
    d = rotr64(d ^ a, 16);
    c = blamka(c, d);
    b = rotr64(b ^ c, 63);
}

DEV inline uint32_t ref_index_alpha(uint32_t slice, uint32_t index, uint32_t pseudo_rand) {
    uint32_t reference_area_size = slice * ARGON2_SEGMENT_LENGTH + index - 1U;
    uint64_t relative = static_cast<uint64_t>(pseudo_rand);
    relative = (relative * relative) >> 32;
    relative = static_cast<uint64_t>(reference_area_size) - 1U -
               ((static_cast<uint64_t>(reference_area_size) * relative) >> 32);
    return static_cast<uint32_t>(relative);
}

DEV inline uint64_t* slot_block(uint64_t* arena, uint32_t slot, uint32_t block_index) {
    return arena + (static_cast<unsigned long long>(slot) * ARGON2_BLOCKS + block_index) * ARGON2_QWORDS;
}

// Full on-device H0 = BLAKE2b-512(params || secret || salt), where the secret
// and the salt-prefix are the same 52-byte `prefix`, and the salt tail is the
// 8-byte big-endian counter.
DEV void make_h0_device(const uint8_t* prefix, uint64_t counter, uint8_t h0[64]) {
    uint8_t input[152];
    uint32_t off = 0;

    store_le32(input + off, ARGON2_PARALLELISM); off += 4;
    store_le32(input + off, HASH_LEN);           off += 4;
    store_le32(input + off, ARGON2_MEMORY_KIB);  off += 4;
    store_le32(input + off, ARGON2_PASSES);      off += 4;
    store_le32(input + off, ARGON2_VERSION);     off += 4;
    store_le32(input + off, ARGON2_TYPE_ID);     off += 4;
    store_le32(input + off, SUBPROOF_LEN);       off += 4;
    copy_bytes(input + off, prefix, SUBPROOF_LEN); off += SUBPROOF_LEN;
    store_le32(input + off, SALT_LEN);           off += 4;
    copy_bytes(input + off, prefix, SUBPROOF_LEN); off += SUBPROOF_LEN;
    store_be64(input + off, counter);            off += 8;
    store_le32(input + off, 0);                  off += 4;
    store_le32(input + off, 0);                  off += 4;

    blake2b_hash(h0, 64, input, off);  // off == 152
}

DEV inline void swap_u64(uint64_t& a, uint64_t& b) {
    uint64_t t = a;
    a = b;
    b = t;
}

DEV inline uint64_t shfl(uint64_t var, int src_lane) {
    return __shfl_sync(0xffffffffU, var, src_lane);
}

// Register-resident transpose for the column pass (hashcat/Mosnáček).
DEV inline void transpose_permute_block(uint64_t R[4], int lane) {
    if (lane & 0x08) { swap_u64(R[0], R[2]); swap_u64(R[1], R[3]); }
    if (lane & 0x04) { swap_u64(R[0], R[1]); swap_u64(R[2], R[3]); }
}

DEV inline int argon2_shift(int idx, int lane) {
    const int delta = ((idx & 0x02) << 3) + (idx & 0x01);
    return (lane & 0x0e) | (((lane & 0x11) + delta + 0x0e) & 0x11);
}

// Full Argon2 block permutation P on a warp-distributed block: lane `lane` holds
// R[idx] = block[idx*32 + lane].  All 32 lanes compute; data is exchanged via
// warp shuffles instead of shared memory.  Ported from hashcat's
// argon2_hash_block (THREADS_PER_LANE == 32 path).
DEV void argon2_permute(uint64_t R[4], int lane) {
    for (int idx = 1; idx < 4; idx++) R[idx] = shfl(R[idx], lane ^ (idx << 2));
    transpose_permute_block(R, lane);
    for (int idx = 1; idx < 4; idx++) R[idx] = shfl(R[idx], lane ^ (idx << 2));
    argon2_g(R[0], R[1], R[2], R[3]);
    for (int idx = 1; idx < 4; idx++) R[idx] = shfl(R[idx], (lane & 0x1c) | ((lane + idx) & 0x03));
    argon2_g(R[0], R[1], R[2], R[3]);
    for (int idx = 1; idx < 4; idx++) R[idx] = shfl(R[idx], ((lane & 0x1c) | ((lane - idx) & 0x03)) ^ (idx << 2));
    transpose_permute_block(R, lane);
    for (int idx = 1; idx < 4; idx++) R[idx] = shfl(R[idx], lane ^ (idx << 2));
    argon2_g(R[0], R[1], R[2], R[3]);
    for (int idx = 1; idx < 4; idx++) R[idx] = shfl(R[idx], argon2_shift(idx, lane));
    argon2_g(R[0], R[1], R[2], R[3]);
    for (int idx = 1; idx < 4; idx++) R[idx] = shfl(R[idx], argon2_shift(4 - idx, lane));
}

// out = P(prev ^ ref) ^ (prev ^ ref), distributed across the warp.  No shared
// memory and no barriers — the shuffles are warp-synchronous.
DEV void fill_block_device(const uint64_t* prev, const uint64_t* ref, uint64_t* out, int lane) {
    uint64_t R[4], tmp[4];
#pragma unroll
    for (int idx = 0; idx < 4; idx++) {
        uint32_t q = static_cast<uint32_t>(idx) * WARP_SIZE + static_cast<uint32_t>(lane);
        R[idx] = prev[q] ^ ref[q];
        tmp[idx] = R[idx];
    }
    argon2_permute(R, lane);
#pragma unroll
    for (int idx = 0; idx < 4; idx++) {
        uint32_t q = static_cast<uint32_t>(idx) * WARP_SIZE + static_cast<uint32_t>(lane);
        out[q] = R[idx] ^ tmp[idx];
    }
}

DEV void argon2id_hash_device(
    uint64_t* arena, uint32_t slot, const uint8_t* prefix, uint64_t counter,
    const uint32_t* i_refs, uint8_t digest[HASH_LEN], int lane) {
    if (lane == 0) {
        uint8_t h0[64];
        make_h0_device(prefix, counter, h0);
        hprime_1024_initial_block(slot_block(arena, slot, 0), h0, 0);
        hprime_1024_initial_block(slot_block(arena, slot, 1), h0, 1);
    }
    // Make lane 0's two initial blocks visible to the rest of the warp.
    __threadfence_block();
    __syncwarp();

    // No per-block barrier: in each iteration a lane reads back only the global
    // qwords it wrote itself (prev/ref at stride-32), which same-thread program
    // order already guarantees.  The one cross-lane value — block(j-1)[0] for the
    // data-dependent reference — is read by its writer (lane 0) and broadcast.
    for (uint32_t j = 2; j < ARGON2_BLOCKS; ++j) {
        uint32_t slice = j / ARGON2_SEGMENT_LENGTH;
        uint32_t index = j % ARGON2_SEGMENT_LENGTH;
        uint32_t ref_index;
        if (slice < 2) {
            ref_index = i_refs[j];
        } else {
            uint64_t v = (lane == 0) ? slot_block(arena, slot, j - 1U)[0] : 0;
            v = shfl(v, 0);
            ref_index = ref_index_alpha(slice, index, static_cast<uint32_t>(v));
        }
        fill_block_device(
            slot_block(arena, slot, j - 1U),
            slot_block(arena, slot, ref_index),
            slot_block(arena, slot, j),
            lane);
    }

    // All lanes wrote the final block; fence before lane 0 reads it whole.
    __threadfence_block();
    __syncwarp();
    if (lane == 0) {
        hprime_32_from_1024_block(digest, slot_block(arena, slot, ARGON2_BLOCKS - 1U));
    }
}

}  // namespace

// Sweep counters [base_counter, base_counter+count) across all slots, looking
// for an argon2id digest with >= proof_difficulty leading zero bits.  On a hit,
// the first warp to win records its counter and digest via found_state CAS.
extern "C" __global__ void argon2id_search_kernel(
    uint64_t* arena,
    const uint32_t* i_refs,
    const uint8_t* prefix,                 // [SUBPROOF_LEN]
    uint32_t proof_difficulty,
    unsigned long long base_counter,
    unsigned long long count,
    uint32_t slot_count,
    int* found_state,
    unsigned long long* found_counter,
    uint8_t* found_digest) {
    int lane = static_cast<int>(threadIdx.x & (WARP_SIZE - 1U));
    uint32_t warp_in_block = threadIdx.x >> 5;
    uint32_t slot = blockIdx.x * WARPS_PER_BLOCK + warp_in_block;
    if (slot >= slot_count) return;

    uint8_t digest[HASH_LEN];  // only lane 0's copy is read

    for (unsigned long long off = slot; off < count; off += slot_count) {
        int stop = 0;
        if (lane == 0) stop = *found_state;
        stop = __shfl_sync(0xffffffffU, stop, 0);
        if (stop != 0) return;

        unsigned long long counter = base_counter + off;
        argon2id_hash_device(arena, slot, prefix, counter, i_refs, digest, lane);

        if (lane == 0 && leading_zero_bits_raw(digest) >= proof_difficulty) {
            if (atomicCAS(found_state, 0, 1) == 0) {
                *found_counter = counter;
                for (uint32_t i = 0; i < HASH_LEN; ++i) found_digest[i] = digest[i];
            }
        }
        __syncwarp();
    }
}
