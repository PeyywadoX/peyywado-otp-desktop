use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

pub const EPOCH: i64 = 946652400;

pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect()
}

fn dynamic_truncate(hash: &[u8], digits: u32) -> String {
    let off = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = (((hash[off] & 0x7f) as u64) << 24)
        | ((hash[off + 1] as u64) << 16)
        | ((hash[off + 2] as u64) << 8)
        | (hash[off + 3] as u64);
    let code = bin % 10u64.pow(digits);
    format!("{:0width$}", code, width = digits as usize)
}

pub fn totp(seed: &[u8], kind: &str, period: u32, digits: u32, now: i64) -> (String, String, u32) {
    let period = if period == 0 { 60 } else { period };
    let digits = if (4..=10).contains(&digits) { digits } else { 6 };
    let diff = now - EPOCH;
    let step = (diff / period as i64) as u32;
    let rem = period - (diff.rem_euclid(period as i64)) as u32;

    let code_for = |s: u32| -> String {
        let msg = s.to_be_bytes();
        let hash: Vec<u8> = if kind == "classic" {
            let key = &seed[..seed.len().min(20)];
            let mut m = <Hmac<Sha1>>::new_from_slice(key).expect("hmac");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        } else {
            let mut key = [0u8; 32];
            let n = seed.len().min(32);
            key[..n].copy_from_slice(&seed[..n]);
            let mut m = <Hmac<Sha256>>::new_from_slice(&key).expect("hmac");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        };
        dynamic_truncate(&hash, digits)
    };

    (code_for(step), code_for(step + 1), rem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_verified_vectors() {

        let plus = hex_to_bytes(&"11".repeat(32));
        let (c, _, _) = totp(&plus, "plus", 60, 6, 1700000000);
        assert_eq!(c, "709288", "plus/SHA256 vektörü");

        let classic = hex_to_bytes(&"22".repeat(20));
        let (c2, _, _) = totp(&classic, "classic", 60, 6, 1700000000);
        assert_eq!(c2, "907054", "classic/SHA1 vektörü");

        let plus2 = hex_to_bytes("3132333435363738393031323334353637383930");
        let (c3, _, _) = totp(&plus2, "plus", 60, 6, 1700000000);
        assert_eq!(c3, "598513", "plus kısa anahtar vektörü");
    }

    #[test]
    fn remaining_in_range() {
        let s = hex_to_bytes(&"11".repeat(32));
        let (_, _, rem) = totp(&s, "plus", 60, 6, 1700000000);
        assert!(rem >= 1 && rem <= 60);
    }
}
