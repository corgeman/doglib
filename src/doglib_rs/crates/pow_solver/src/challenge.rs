use base64::prelude::*;

const VERSION: &str = "s";

pub struct Challenge {
    pub difficulty: u32,
    pub val: Vec<u8>,
}

impl Challenge {
    /// Parse a challenge string like "s.AAATiA==.c5JzfKLC099PHb3WLBaz1g=="
    pub fn decode(challenge: &str) -> Result<Self, &'static str> {
        let mut parts = challenge.split('.');
        if parts.next() != Some(VERSION) {
            return Err("incorrect version");
        }
        let segments: Vec<_> = parts.collect();
        if segments.len() != 2 {
            return Err("incorrect number of parts");
        }

        let diff_bytes = BASE64_STANDARD
            .decode(segments[0])
            .map_err(|_| "difficulty is not valid base64")?;
        let val_bytes = BASE64_STANDARD
            .decode(segments[1])
            .map_err(|_| "value is not valid base64")?;

        if diff_bytes.len() > 4 {
            let (prefix, last4) = diff_bytes.split_at(diff_bytes.len() - 4);
            if prefix.iter().any(|&b| b != 0) {
                return Err("difficulty too large");
            }
            let difficulty = u32::from_be_bytes(last4.try_into().unwrap());
            Ok(Self {
                difficulty,
                val: val_bytes,
            })
        } else {
            let mut buf = [0u8; 4];
            buf[4 - diff_bytes.len()..].copy_from_slice(&diff_bytes);
            Ok(Self {
                difficulty: u32::from_be_bytes(buf),
                val: val_bytes,
            })
        }
    }

    /// Decode from raw bytes (no UTF-8 validation needed since we only look at ASCII).
    pub fn decode_bytes(challenge: &[u8]) -> Result<Self, &'static str> {
        let s = core::str::from_utf8(challenge).map_err(|_| "challenge is not valid UTF-8")?;
        Self::decode(s)
    }

    /// Encode a solution value into the response format "s.<base64 value>"
    pub fn encode_solution(val_bytes: &[u8]) -> String {
        format!("{}.{}", VERSION, BASE64_STANDARD.encode(val_bytes))
    }

    /// Encode a solution value, returning raw bytes.
    pub fn encode_solution_bytes(val_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + val_bytes.len() * 4 / 3 + 4);
        out.extend_from_slice(VERSION.as_bytes());
        out.push(b'.');
        let b64 = BASE64_STANDARD.encode(val_bytes);
        out.extend_from_slice(b64.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_basic() {
        let c = Challenge::decode("s.AAAAMg==.H+fPiuL32DPbfN97cpd0nA==").unwrap();
        assert_eq!(c.difficulty, 50);
        assert_eq!(c.val.len(), 16);
    }

    #[test]
    fn decode_bad_version() {
        assert!(Challenge::decode("x.AAAAMg==.H+fPiuL32DPbfN97cpd0nA==").is_err());
    }
}
