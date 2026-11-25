use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;

use crate::otp::hex_to_bytes;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeydownHeader {
    pub random: String,
    pub userno: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeydownResult {
    pub uid: String,
    pub ccd: String,
    pub userno: String,
    pub seed: String,
    pub serial: String,
    pub expire_ms: u64,
    pub otppin: i64,
}

#[derive(Deserialize)]
struct RawOtpData {
    otpsecukey: String,
    #[serde(default)]
    serialkey: String,
    #[serde(default)]
    expire: u64,
    #[serde(default)]
    otppin: i64,
}

#[derive(Deserialize)]
struct OuterKeydownResponse {
    result: String,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Deserialize)]
struct InnerEnvelope {
    header: String,
    data: String,
}

fn aes256_cbc_decrypt(ct: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, String> {
    if ct.is_empty() || ct.len() % 16 != 0 {
        return Err(format!("geçersiz AES-CBC blok uzunluğu: {}", ct.len()));
    }
    let mut buf = ct.to_vec();
    let dec = Aes256CbcDec::new(key.into(), iv.into());
    match dec.decrypt_padded_mut::<Pkcs7>(&mut buf) {
        Ok(pt) => Ok(pt.to_vec()),
        Err(_) => {

            let mut raw = ct.to_vec();
            let dec2 = Aes256CbcDec::new(key.into(), iv.into());
            let pt = dec2
                .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut raw)
                .map_err(|_| "AES-256-CBC çözme hatası".to_string())?;
            if let Some(&pad) = pt.last() {
                let p = pad as usize;
                if (1..=16).contains(&p)
                    && pt.len() >= p
                    && pt[pt.len() - p..].iter().all(|&b| b == pad)
                {
                    return Ok(pt[..pt.len() - p].to_vec());
                }
            }
            Ok(pt.to_vec())
        }
    }
}

pub fn decrypt_header(header: &[u8]) -> Result<KeydownHeader, String> {
    if header.len() < 48 {
        return Err(format!("header çok kısa ({} bayt)", header.len()));
    }
    let n = header.len();
    let ct = &header[..n - 32];
    let salt = &header[n - 32..n - 16];
    let iv_slice = &header[n - 16..n];

    let key: [u8; 32] = Sha256::digest(salt).into();
    let iv: [u8; 16] = iv_slice
        .try_into()
        .map_err(|_| "header IV 16 bayt değil".to_string())?;

    let pt = aes256_cbc_decrypt(ct, &key, &iv)?;
    serde_json::from_slice(&pt).map_err(|e| format!("header JSON çözülemedi: {e}"))
}

pub fn decode_keydown(header_hex: &str, data_hex: &str) -> Result<KeydownResult, String> {
    let hdr_bytes = hex_to_bytes(header_hex);
    let data_bytes = hex_to_bytes(data_hex);

    let hdr = decrypt_header(&hdr_bytes)?;
    let keyarg = format!("{}{}", hdr.userno, hdr.random);

    let siv: [u8; 32] = Sha256::digest(keyarg.as_bytes()).into();
    let key2: [u8; 32] = Sha256::digest(&siv[..16]).into();
    let iv2: [u8; 16] = siv[16..32]
        .try_into()
        .map_err(|_| "data IV 16 bayt değil".to_string())?;

    let gz_bytes = aes256_cbc_decrypt(&data_bytes, &key2, &iv2)?;
    let mut gz = GzDecoder::new(&gz_bytes[..]);
    let mut json_str = String::new();
    gz.read_to_string(&mut json_str)
        .map_err(|e| format!("gzip açılamadı: {e}"))?;

    let raw: RawOtpData =
        serde_json::from_str(&json_str).map_err(|e| format!("OTP_DATA JSON çözülemedi: {e}"))?;

    let seed = raw.otpsecukey.trim().to_ascii_uppercase();
    if seed.len() < 32 || !seed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("geçersiz otpsecukey (seed) formatı".into());
    }

    let (ccd, uid) = match hdr.userno.split_once('@') {
        Some((c, u)) => (c.to_string(), u.to_string()),
        None => (String::new(), hdr.userno.clone()),
    };

    Ok(KeydownResult {
        uid,
        ccd,
        userno: hdr.userno,
        seed,
        serial: raw.serialkey,
        expire_ms: raw.expire,
        otppin: raw.otppin,
    })
}

pub fn parse_keydown_response(body: &[u8]) -> Result<Option<KeydownResult>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "yanıt UTF-8 değil".to_string())?;
    let trimmed = text.trim();
    if !trimmed.starts_with('{') {
        return Ok(None);
    }
    let outer: OuterKeydownResponse = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if outer.result != "PB0000" {
        return Err(format!("Aktivasyon reddedildi ({})", outer.result));
    }
    let env: InnerEnvelope = match &outer.data {
        serde_json::Value::String(s) => {
            serde_json::from_str(s).map_err(|e| format!("iç data JSON ayrıştırılamadı: {e}"))?
        }
        serde_json::Value::Object(_) => serde_json::from_value(outer.data)
            .map_err(|e| format!("iç data nesnesi ayrıştırılamadı: {e}"))?,
        _ => return Err("keydown yanıtında data alanı eksik".into()),
    };
    decode_keydown(&env.header, &env.data).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockEncryptMut;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02X}", b)).collect()
    }

    fn encrypt_synthetic_envelope(
        userno: &str,
        random: &str,
        seed: &str,
        serial: &str,
    ) -> (String, String) {
        let salt: [u8; 16] = *b"0123456789ABCDEF";
        let iv: [u8; 16] = *b"FEDCBA9876543210";
        let key: [u8; 32] = Sha256::digest(salt).into();

        let hdr_json = format!(r#"{{"random":"{}","userno":"{}"}}"#, random, userno);
        let mut hdr_buf = vec![0u8; hdr_json.len() + 32];
        hdr_buf[..hdr_json.len()].copy_from_slice(hdr_json.as_bytes());
        let ct = Aes256CbcEnc::new((&key).into(), (&iv).into())
            .encrypt_padded_mut::<Pkcs7>(&mut hdr_buf, hdr_json.len())
            .unwrap();
        let mut header_full = ct.to_vec();
        header_full.extend_from_slice(&salt);
        header_full.extend_from_slice(&iv);

        let otp_json = format!(
            r#"{{"change":"0","expire":2556054000000,"serialkey":"{}","otppin":5,"otpsecukey":"{}","rescode":6}}"#,
            serial, seed
        );
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(otp_json.as_bytes()).unwrap();
        let gz_bytes = gz.finish().unwrap();

        let keyarg = format!("{}{}", userno, random);
        let siv: [u8; 32] = Sha256::digest(keyarg.as_bytes()).into();
        let key2: [u8; 32] = Sha256::digest(&siv[..16]).into();
        let iv2: [u8; 16] = siv[16..32].try_into().unwrap();

        let mut data_buf = vec![0u8; gz_bytes.len() + 32];
        data_buf[..gz_bytes.len()].copy_from_slice(&gz_bytes);
        let ct2 = Aes256CbcEnc::new((&key2).into(), (&iv2).into())
            .encrypt_padded_mut::<Pkcs7>(&mut data_buf, gz_bytes.len())
            .unwrap();

        (to_hex(&header_full), to_hex(ct2))
    }

    #[test]
    fn roundtrip_synthetic_keydown_response() {
        let seed = "AABBCCDDEEFF00112233445566778899AABBCCDD";
        let (h, d) = encrypt_synthetic_envelope("1637@NT0000001", "1234567890", seed, "998877665");

        let inner = serde_json::json!({ "header": h, "data": d }).to_string();
        let outer = serde_json::json!({ "result": "PB0000", "data": inner }).to_string();

        let parsed = parse_keydown_response(outer.as_bytes())
            .expect("ok")
            .expect("some");
        assert_eq!(parsed.uid, "NT0000001");
        assert_eq!(parsed.ccd, "1637");
        assert_eq!(parsed.seed, seed);
        assert_eq!(parsed.serial, "998877665");
        assert_eq!(parsed.expire_ms, 2556054000000);
        assert_eq!(parsed.otppin, 5);
    }

    #[test]
    fn rejects_error_result_code() {
        let body = br#"{"result":"SE3011","data":""}"#;
        let err = parse_keydown_response(body).unwrap_err();
        assert!(err.contains("SE3011"));
    }
}
