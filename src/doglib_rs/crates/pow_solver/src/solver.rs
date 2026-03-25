use crate::challenge::Challenge;
use crate::field::Fe1279;

#[cfg(target_arch = "x86_64")]
use crate::field_avx512;

/// Solve a POW challenge from raw bytes, returning solution as raw bytes.
pub fn solve_bytes(challenge: &[u8]) -> Result<Vec<u8>, &'static str> {
    let c = Challenge::decode_bytes(challenge)?;
    let mut fe = Fe1279::from_be_bytes(&c.val);

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512ifma")
            && std::arch::is_x86_feature_detected!("avx512f")
        {
            unsafe { field_avx512::solve_inner(&mut fe, c.difficulty) };
            let mut out = [0u8; 168];
            let n = fe.to_be_bytes(&mut out);
            return Ok(Challenge::encode_solution_bytes(&out[..n]));
        }
    }

    solve_scalar(&mut fe, c.difficulty);
    let mut out = [0u8; 168];
    let n = fe.to_be_bytes(&mut out);
    Ok(Challenge::encode_solution_bytes(&out[..n]))
}

/// Solve a POW challenge string, returning the solution string.
/// Automatically selects the fastest available backend.
pub fn solve(challenge_str: &str) -> Result<String, &'static str> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512ifma")
            && std::arch::is_x86_feature_detected!("avx512f")
        {
            return solve_with("avx512", challenge_str);
        }
    }

    solve_with("scalar", challenge_str)
}

/// Solve with a specific backend ("scalar" or "avx512").
pub fn solve_with(backend: &str, challenge_str: &str) -> Result<String, &'static str> {
    let challenge = Challenge::decode(challenge_str)?;
    let mut fe = Fe1279::from_be_bytes(&challenge.val);

    match backend {
        #[cfg(target_arch = "x86_64")]
        "avx512" => unsafe { field_avx512::solve_inner(&mut fe, challenge.difficulty) },
        "scalar" | _ => solve_scalar(&mut fe, challenge.difficulty),
    }

    let mut out = [0u8; 168];
    let n = fe.to_be_bytes(&mut out);
    Ok(Challenge::encode_solution(&out[..n]))
}

fn solve_scalar(fe: &mut Fe1279, difficulty: u32) {
    for _ in 0..difficulty {
        fe.sqrt_step();
        fe.xor_one();
    }
}
