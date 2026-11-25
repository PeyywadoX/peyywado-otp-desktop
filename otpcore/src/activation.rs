use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chrono::Local;
use num_bigint::BigUint;
use rand::RngCore;
use serde::Serialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

type Enc = cbc::Encryptor<Aes128>;
type Dec = cbc::Decryptor<Aes128>;

pub const OTP_HOST: &str = "otpsvr.nttgame.com";
pub const OTP_PORT: u16 = 27700;
const FIXED_PHONE: &str = "01099112766";
const FIXED_MERCHANT: &str = "6802011212121";

pub const REAL_DEVICE_CODENAMES: &[&str] = &[
    "beyond1", "beyond2", "a51", "a52q", "a71", "d2s", "star2qlte", "crownqlte",
    "dreamlte", "greatlte", "o1s", "r8q", "bramble", "redfin",
];

#[derive(Serialize, Debug, Clone)]
pub struct OtpData {
    pub seed: String,
    pub serial: String,
    pub lock_count: String,
    pub expire_date: String,
    pub kind: String,
    pub period: u32,
    pub digits: u32,
}

fn to_fixed_be(n: &BigUint, len: usize) -> Vec<u8> {
    let b = n.to_bytes_be();
    if b.len() >= len {
        b[b.len() - len..].to_vec()
    } else {
        let mut o = vec![0u8; len - b.len()];
        o.extend_from_slice(&b);
        o
    }
}

fn read_mpi(buf: &[u8], off: &mut usize) -> Result<(BigUint, usize), String> {
    if *off + 2 > buf.len() {
        return Err("DH param kısa".into());
    }
    let n = ((buf[*off] as usize) << 8) | buf[*off + 1] as usize;
    *off += 2;
    if *off + n > buf.len() {
        return Err("DH param değeri taşıyor".into());
    }
    let v = BigUint::from_bytes_be(&buf[*off..*off + n]);
    *off += n;
    Ok((v, n))
}

fn recv_exact(s: &mut TcpStream, n: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; n];
    s.read_exact(&mut out).map_err(|e| format!("okuma: {e}"))?;
    Ok(out)
}

fn be_u32(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

fn put(rec: &mut [u8], off: usize, s: &[u8]) {
    rec[off..off + s.len()].copy_from_slice(s);
}

fn build_record(cmd: &str, payload: &[u8], device: &str) -> Vec<u8> {
    let total = 94 + payload.len();
    let mut rec = vec![0x20u8; total];

    rec[0..4].copy_from_slice(&be_u32(payload.len() as u32));
    put(&mut rec, 4, cmd.as_bytes());
    put(&mut rec, 9, b"1");
    put(&mut rec, 10, FIXED_PHONE.as_bytes());
    put(&mut rec, 24, b"MSA");
    let dev = device.as_bytes();
    let dl = dev.len().min(15);
    put(&mut rec, 27, &dev[..dl]);
    put(&mut rec, 42, b"010001");
    put(&mut rec, 48, FIXED_MERCHANT.as_bytes());
    put(&mut rec, 61, b"PB0000");

    let now = Local::now().format("%y%m%d%I%M%S").to_string();
    put(&mut rec, 67, &now.as_bytes()[0..6]);
    put(&mut rec, 73, &now.as_bytes()[6..12]);
    put(&mut rec, 79, b"1");
    put(&mut rec, 80, b"0023");
    put(&mut rec, 94, payload);
    rec
}

fn parse_otp_data(s: &str) -> Result<OtpData, String> {
    if s.len() < 40 {
        return Err(format!("OTP_DATA kısa: '{}'", &s[..s.len().min(40)]));
    }
    let chars: Vec<char> = s.chars().collect();
    let take = |a: usize, b: usize| -> String {
        chars[a.min(chars.len())..b.min(chars.len())].iter().collect::<String>()
    };
    let seed_hex = take(0, 40);
    if seed_hex.len() != 40 || !seed_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("geçersiz seed: '{}'", seed_hex));
    }
    Ok(OtpData {
        seed: seed_hex,
        serial: take(40, 52).trim().to_string(),
        lock_count: take(56, 58).trim().to_string(),
        expire_date: take(58, 66).trim().to_string(),
        kind: "classic".into(),
        period: 60,
        digits: 6,
    })
}

pub fn pick_device(randomize: bool) -> String {
    if randomize {
        let i = (rand::random::<u32>() as usize) % REAL_DEVICE_CODENAMES.len();
        REAL_DEVICE_CODENAMES[i].to_string()
    } else {
        "beyond1".to_string()
    }
}

pub fn activate(
    otp_id: &str,
    auth_code: &str,
    device: Option<&str>,
    timeout_secs: u64,
) -> Result<OtpData, String> {
    let otp_id = otp_id.trim();
    let auth_code = auth_code.trim();
    if otp_id.is_empty() || auth_code.len() < 6 {
        return Err("OTP ID ve 6 haneli aktivasyon kodu gereklidir".into());
    }
    let device = device.map(|d| d.to_string()).unwrap_or_else(|| pick_device(false));

    let pass_str = format!("{otp_id}{auth_code}");
    let mut passcode = vec![0x20u8; 42];
    let pb = pass_str.as_bytes();
    let pl = pb.len().min(42);
    passcode[..pl].copy_from_slice(&pb[..pl]);

    let mut sock = TcpStream::connect((OTP_HOST, OTP_PORT))
        .map_err(|e| format!("bağlantı: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(timeout_secs))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(timeout_secs))).ok();

    let plen = u32::from_be_bytes(recv_exact(&mut sock, 4)?.try_into().unwrap()) as usize;
    if plen == 0 || plen > 65535 {
        return Err(format!("geçersiz DH param uzunluğu: {plen}"));
    }
    let params = recv_exact(&mut sock, plen)?;
    let mut off = 0usize;
    let (p, p_len) = read_mpi(&params, &mut off)?;
    let (g, _) = read_mpi(&params, &mut off)?;
    let (gy, _) = read_mpi(&params, &mut off)?;

    let (gx_bytes, session) = loop {
        let mut xb = [0u8; 256];
        rand::thread_rng().fill_bytes(&mut xb);
        let x = (BigUint::from_bytes_be(&xb) % (&p - 2u32)) + 1u32;
        let gx = g.modpow(&x, &p);
        let gxb = to_fixed_be(&gx, p_len);
        if gxb[0] <= 0x80 {
            let k = gy.modpow(&x, &p);
            let kb = to_fixed_be(&k, p_len);
            break (gxb, kb[..32].to_vec());
        }
    };
    let key: [u8; 16] = session[0..16].try_into().unwrap();
    let iv: [u8; 16] = session[16..32].try_into().unwrap();

    sock.write_all(&be_u32(gx_bytes.len() as u32)).map_err(|e| e.to_string())?;
    sock.write_all(&gx_bytes).map_err(|e| e.to_string())?;

    let record = build_record("CM008", &passcode, &device);
    let ct = Enc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&record);
    sock.write_all(&be_u32(ct.len() as u32)).map_err(|e| e.to_string())?;
    sock.write_all(&ct).map_err(|e| e.to_string())?;

    let rlen = u32::from_be_bytes(recv_exact(&mut sock, 4)?.try_into().unwrap()) as usize;
    if rlen == 0 || rlen > 65535 {
        return Err(format!("geçersiz yanıt uzunluğu: {rlen}"));
    }
    let resp_ct = recv_exact(&mut sock, rlen)?;
    let resp = Dec::new(&key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&resp_ct)
        .map_err(|_| "yanıt çözülemedi (padding)".to_string())?;

    if resp.len() < 94 {
        return Err(format!("kısa yanıt ({} bayt)", resp.len()));
    }
    let res_code = String::from_utf8_lossy(&resp[61..67]).trim().to_string();
    let pay_len = u32::from_be_bytes(resp[0..4].try_into().unwrap()) as usize;
    let end = (94 + pay_len).min(resp.len());
    let body = String::from_utf8_lossy(&resp[94..end]).to_string();

    if res_code == "PB0000" {
        let mut data = parse_otp_data(&body)?;
        if data.serial.is_empty() {
            data.serial = otp_id.to_string();
        }
        Ok(data)
    } else {
        Err(format!("Sunucu reddetti (RES_CODE={res_code}): {}", body.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_layout() {
        let rec = build_record("CM008", &vec![b'X'; 42], "beyond1");
        assert_eq!(rec.len(), 94 + 42);
        assert_eq!(u32::from_be_bytes(rec[0..4].try_into().unwrap()), 42);
        assert_eq!(&rec[4..9], b"CM008");
        assert_eq!(&rec[10..21], b"01099112766");
        assert_eq!(&rec[24..27], b"MSA");
        assert_eq!(&rec[27..34], b"beyond1");
        assert_eq!(&rec[42..48], b"010001");
        assert_eq!(&rec[48..61], b"6802011212121");
        assert_eq!(&rec[61..67], b"PB0000");
        assert_eq!(&rec[80..84], b"0023");
        assert_eq!(&rec[94..94 + 42], &vec![b'X'; 42][..]);

        let hh: u32 = String::from_utf8_lossy(&rec[73..75]).parse().unwrap();
        assert!((1..=12).contains(&hh));
    }

    #[test]
    fn parse_otp_data_seed() {
        let s = format!(
            "{}{}{}{}{}{}",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "SER000000001", "00", "00", "05", "29991231"
        );
        let d = parse_otp_data(&s).unwrap();
        assert_eq!(d.seed, "0123456789ABCDEF0123456789ABCDEF01234567");
        assert_eq!(d.serial, "SER000000001");
        assert_eq!(d.expire_date, "29991231");
    }
}
