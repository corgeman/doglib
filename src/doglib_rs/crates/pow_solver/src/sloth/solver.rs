use super::challenge::Challenge;
use super::field::Fe1279;

#[cfg(target_arch = "x86_64")]
use super::{field_avx512, field_avx512vl};

#[cfg(target_arch = "x86_64")]
fn prefers_avx512vl(vendor: [u32; 3], signature: u32) -> bool {
    if vendor != [0x68747541, 0x69746e65, 0x444d4163] {
        return false;
    }
    let base_family = (signature >> 8) & 0xf;
    let base_model = (signature >> 4) & 0xf;
    let family = if base_family == 0xf {
        base_family + ((signature >> 20) & 0xff)
    } else {
        base_family
    };
    let model = if matches!(base_family, 0x6 | 0xf) {
        base_model | (((signature >> 16) & 0xf) << 4)
    } else {
        base_model
    };
    // Zen 4 / Zen 4c tuning allowlist, not an ISA availability check:
    // https://github.com/llvm/llvm-project/blob/main/llvm/lib/TargetParser/Host.cpp
    family == 0x19
        && matches!(model, 0x10..=0x1f | 0x60..=0x6f | 0x70..=0x77 | 0x78..=0x7f | 0xa0..=0xaf)
}

#[cfg(target_arch = "x86_64")]
fn select_backend(wide_supported: bool, vl_supported: bool, prefer_vl: bool) -> &'static str {
    if !wide_supported {
        "scalar"
    } else if vl_supported && prefer_vl {
        "avx512vl"
    } else {
        "avx512"
    }
}

/// Return the cached backend used by automatic Sloth solves.
pub fn selected_backend() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        static BACKEND: std::sync::LazyLock<&'static str> = std::sync::LazyLock::new(|| {
            let wide_supported = field_avx512::is_supported();
            if !wide_supported {
                return "scalar";
            }
            let vl_supported = field_avx512vl::is_supported();
            if !vl_supported {
                return "avx512";
            }
            let leaf0 = core::arch::x86_64::__cpuid(0);
            let prefer_vl = leaf0.eax >= 1 && prefers_avx512vl(
                [leaf0.ebx, leaf0.edx, leaf0.ecx],
                core::arch::x86_64::__cpuid(1).eax,
            );
            select_backend(wide_supported, vl_supported, prefer_vl)
        });
        *BACKEND
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "scalar"
    }
}

fn solve_field(fe: &mut Fe1279, difficulty: u32, backend: &str) -> Result<(), &'static str> {
    match backend {
        #[cfg(target_arch = "x86_64")]
        "avx512" if field_avx512::is_supported() => {
            // SAFETY: the guard checks all required CPU and OS features.
            unsafe { field_avx512::solve_inner(fe, difficulty) };
        }
        #[cfg(target_arch = "x86_64")]
        "avx512vl" if field_avx512vl::is_supported() => {
            // SAFETY: the guard checks all required CPU and OS features.
            unsafe { field_avx512vl::solve_inner(fe, difficulty) };
        }
        "avx512" => return Err("AVX-512 IFMA is unavailable"),
        "avx512vl" => return Err("AVX-512 IFMA and VL are unavailable"),
        _ => solve_scalar(fe, difficulty),
    }
    Ok(())
}

/// Solve a POW challenge from raw bytes, returning solution as raw bytes.
pub fn solve_bytes(challenge: &[u8]) -> Result<Vec<u8>, &'static str> {
    let c = Challenge::decode_bytes(challenge)?;
    let mut fe = Fe1279::from_be_bytes(&c.val);

    solve_field(&mut fe, c.difficulty, selected_backend())?;
    let mut out = [0u8; 168];
    let n = fe.to_be_bytes(&mut out);
    Ok(Challenge::encode_solution_bytes(&out[..n]))
}

/// Solve a POW challenge string, returning the solution string.
/// Automatically selects the available backend preferred for this CPU.
pub fn solve(challenge_str: &str) -> Result<String, &'static str> {
    solve_with(selected_backend(), challenge_str)
}

/// Solve with a specific backend ("scalar", "avx512", or "avx512vl").
/// Returns an error if the explicitly requested AVX-512 backend is unavailable.
pub fn solve_with(backend: &str, challenge_str: &str) -> Result<String, &'static str> {
    let challenge = Challenge::decode(challenge_str)?;
    let mut fe = Fe1279::from_be_bytes(&challenge.val);

    solve_field(&mut fe, challenge.difficulty, backend)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn zen4_preference_allowlist() {
        let amd = [0x68747541, 0x69746e65, 0x444d4163];
        assert!(prefers_avx512vl(amd, 0x00a70f41));
        for stepping in 0..16 {
            assert!(prefers_avx512vl(amd, 0x00a70f40 | stepping));
        }
        for signature in [
            0x00a10f00, 0x00a10ff0, 0x00a60f00, 0x00a60ff0, 0x00a70f00,
            0x00a70f70, 0x00a70f80, 0x00a70ff0, 0x00aa0f00, 0x00aa0ff0,
        ] {
            assert!(prefers_avx512vl(amd, signature), "{signature:#010x}");
        }
        for signature in [
            0x00a00ff0, 0x00a20f00, 0x00a50ff0, 0x00a80f00, 0x00a90ff0,
            0x00ab0f00, 0x00a20f10, 0x00b40f40, 0,
        ] {
            assert!(!prefers_avx512vl(amd, signature), "{signature:#010x}");
        }
        for vendor in [
            [0x756e6547, 0x49656e69, 0x6c65746e],
            [0; 3],
            [amd[0], amd[2], amd[1]],
        ] {
            assert!(!prefers_avx512vl(vendor, 0x00a70f41), "{vendor:x?}");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn backend_feature_precedence() {
        for (wide, vl, prefer, expected) in [
            (false, false, false, "scalar"),
            (false, false, true, "scalar"),
            (false, true, false, "scalar"),
            (false, true, true, "scalar"),
            (true, false, false, "avx512"),
            (true, false, true, "avx512"),
            (true, true, false, "avx512"),
            (true, true, true, "avx512vl"),
        ] {
            assert_eq!(select_backend(wide, vl, prefer), expected, "{wide}, {vl}, {prefer}");
        }
    }

    #[test]
    fn solver_entrypoint_contract() {
        let challenge = "s.AAAAAQ==.H+fPiuL32DPbfN97cpd0nA==";
        let expected = "s.SehdFNCoMtQI4d9JBXsmzWdYk77jtb36Io5acLmjB6l/Vr1VUUsegi3CNbUf7lgUI5kGuxgdleSh+poE/BCGoAoaTNGVBC14jl+W0D7wg8R2IPDCUSTueG0JNCtJL8OeNPiReJ+CBFcqcR0Ntc9Qakzm8sZaBjGld1Rh3FK6gresUqjpnxGS4SgIg/lp/iZ+2EetM94ewJHsXghGaWQYkg==";
        assert_eq!(solve_with("scalar", challenge).unwrap(), expected);
        assert_eq!(solve_with("unknown", challenge).unwrap(), expected);
        assert_eq!(solve(challenge).unwrap(), expected);
        assert_eq!(solve_bytes(challenge.as_bytes()).unwrap(), expected.as_bytes());

        #[cfg(target_arch = "x86_64")]
        let availability = [field_avx512::is_supported(), field_avx512vl::is_supported()];
        #[cfg(not(target_arch = "x86_64"))]
        let availability = [false; 2];
        for ((backend, error), available) in [
            ("avx512", "AVX-512 IFMA is unavailable"),
            ("avx512vl", "AVX-512 IFMA and VL are unavailable"),
        ].into_iter().zip(availability) {
            let result = solve_with(backend, challenge);
            if available {
                assert_eq!(result.unwrap(), expected, "{backend}");
            } else {
                assert_eq!(result, Err(error), "{backend}");
            }
        }

        let bad = "x.AAAAMg==.H+fPiuL32DPbfN97cpd0nA==";
        assert_eq!(solve(bad), Err("incorrect version"));
        assert_eq!(solve_bytes(bad.as_bytes()), Err("incorrect version"));
        for backend in ["scalar", "avx512", "avx512vl", "unknown"] {
            assert_eq!(solve_with(backend, bad), Err("incorrect version"), "{backend}");
        }
    }
}
