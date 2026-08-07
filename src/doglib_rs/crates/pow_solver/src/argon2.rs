//! Accelerated Argon2id PoW backends for the bbb `a2id.v2` format.

#[cfg(feature = "cuda")]
mod cuda;
mod avx512;

include!(concat!(env!("OUT_DIR"), "/argon2_refs.rs"));

pub(super) const PASSWORD_LEN: usize = 16;
pub(super) const HASH_LEN: usize = 32;
pub(super) const COUNTER_LEN: usize = 8;
pub(super) const SUBPROOF_LEN: usize = PASSWORD_LEN + 4 + HASH_LEN;
pub(super) const ARGON2_BLOCKS: usize = 4096;
pub(super) const ARGON2_SEGMENT_LENGTH: usize = 1024;
const MAX_DIFFICULTY: u32 = 63;
const MAX_SPLIT_BITS: u32 = 3;

pub(super) struct Challenge {
    pub(super) difficulty: u32,
    pub(super) password: [u8; PASSWORD_LEN],
}

fn decode_hex16(value: &str) -> Option<[u8; PASSWORD_LEN]> {
    if value.len() != PASSWORD_LEN * 2 || !value.is_ascii() {
        return None;
    }
    let mut out = [0; PASSWORD_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn parse_challenge(challenge: &str) -> Result<Challenge, String> {
    let mut parts = challenge.trim().split('.');
    if parts.next() != Some("a2id") || parts.next() != Some("v2") {
        return Err(format!("not an a2id.v2 challenge: {challenge:?}"));
    }
    let difficulty = parts
        .next()
        .ok_or_else(|| "bad difficulty".to_string())?
        .parse::<u32>()
        .map_err(|_| "bad difficulty".to_string())?;
    if difficulty > MAX_DIFFICULTY {
        return Err("difficulty out of range".into());
    }
    let password = parts
        .next()
        .and_then(decode_hex16)
        .ok_or_else(|| "bad password hex".to_string())?;
    if parts.next().is_some() {
        return Err(format!("not an a2id.v2 challenge: {challenge:?}"));
    }
    Ok(Challenge { difficulty, password })
}

pub(super) fn proof_shape(difficulty: u32) -> (u32, u32) {
    let split = MAX_SPLIT_BITS.min(difficulty.saturating_sub(1));
    (1 << split, difficulty - split)
}

pub(super) fn build_prefix(
    password: &[u8; PASSWORD_LEN],
    index: u32,
    chain: &[u8; HASH_LEN],
) -> [u8; SUBPROOF_LEN] {
    let mut prefix = [0; SUBPROOF_LEN];
    prefix[..PASSWORD_LEN].copy_from_slice(password);
    prefix[PASSWORD_LEN..PASSWORD_LEN + 4].copy_from_slice(&index.to_be_bytes());
    prefix[PASSWORD_LEN + 4..].copy_from_slice(chain);
    prefix
}

pub fn backend_info() -> &'static str {
    #[cfg(feature = "cuda")]
    if cuda::available() {
        return "cuda";
    }
    if avx512::available() {
        return "avx512";
    }
    "unavailable"
}

pub fn solve(challenge: &str, workers: i64) -> Result<String, String> {
    let challenge = parse_challenge(challenge)?;
    #[cfg(feature = "cuda")]
    let cuda_error = match cuda::solve(&challenge, workers) {
        Ok(solution) => return Ok(solution),
        Err(error) => Some(error),
    };
    #[cfg(not(feature = "cuda"))]
    let cuda_error: Option<String> = None;

    if avx512::available() {
        if let Some(error) = &cuda_error {
            eprintln!(
                "[doglib.pow] GPU argon2 solve failed ({error}); falling back to AVX-512."
            );
        }
        return avx512::solve(&challenge, workers);
    }
    Err(cuda_error.unwrap_or_else(|| "no accelerated Argon2 backend available".to_string()))
}

#[cfg(feature = "cuda")]
pub fn bench(n_launches: u32) -> Result<(u64, f64), String> {
    cuda::bench(n_launches)
}
