use serde::Serialize;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
pub struct CheckResult {
    pub ok: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct SyncResult {
    pub offset: f64,
    pub source: String,
}

fn now_millis() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as f64
}

fn http_get(host: &str, path: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let addr = (host, 80u16)
        .to_socket_addrs()
        .map_err(|e| format!("dns: {e}"))?
        .next()
        .ok_or("dns boş")?;
    let mut s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("bağlantı: {e}"))?;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: PeyywadoOTP/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| e.to_string())?;

    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        let first_line = String::from_utf8_lossy(&buf[..pos])
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        if !first_line.contains(" 200") {
            return Err(format!("HTTP hata yanıtı: {first_line}"));
        }
        Ok(buf[pos + 4..].to_vec())
    } else {
        Err("HTTP yanıt ayrıştırılamadı".into())
    }
}

fn fetch_server_millis(host: &str, timeout: Duration) -> Result<f64, String> {
    let body = http_get(host, "/timesvc/index.jsp", timeout)?;
    if body.len() < 8 {
        return Err(format!("kısa yanıt ({} bayt)", body.len()));
    }
    let ms = i64::from_be_bytes(body[0..8].try_into().unwrap());

    if !(1_577_836_800_000..=4_102_444_800_000).contains(&ms) {
        return Err(format!("geçersiz zaman değeri ({ms})"));
    }
    Ok(ms as f64)
}

pub fn sync_time() -> Result<SyncResult, String> {
    let timeout = Duration::from_secs(3);
    for host in ["time1.dreammirae.com", "time2.dreammirae.com"] {
        let t0 = Instant::now();
        if let Ok(server_ms) = fetch_server_millis(host, timeout) {
            let rtt = t0.elapsed().as_secs_f64() / 2.0;
            let local = now_millis() / 1000.0;
            let offset = (server_ms / 1000.0 + rtt) - local;
            return Ok(SyncResult { offset, source: host.to_string() });
        }
    }
    Err("saat sunucusuna ulaşılamadı".into())
}

pub fn check_one(key: &str) -> CheckResult {
    let timeout = Duration::from_secs(3);
    match key {
        "time1" | "time2" => {
            let host = if key == "time1" { "time1.dreammirae.com" } else { "time2.dreammirae.com" };
            let t0 = Instant::now();
            match fetch_server_millis(host, timeout) {
                Ok(_) => CheckResult {
                    ok: true,
                    detail: format!("{} ms · 8 bayt geçerli", t0.elapsed().as_millis()),
                },
                Err(e) => CheckResult { ok: false, detail: e },
            }
        }
        "ntt" => {
            let addr = (super::activation::OTP_HOST, super::activation::OTP_PORT)
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next());
            match addr {
                Some(a) => {
                    let t0 = Instant::now();
                    match TcpStream::connect_timeout(&a, timeout) {
                        Ok(_) => CheckResult {
                            ok: true,
                            detail: format!("27700 açık · {} ms", t0.elapsed().as_millis()),
                        },
                        Err(e) => CheckResult { ok: false, detail: format!("port kapalı: {e}") },
                    }
                }
                None => CheckResult { ok: false, detail: "DNS çözülemedi".into() },
            }
        }
        "crypto" => {
            let seed = super::otp::hex_to_bytes(&"11".repeat(32));
            let (c, _, _) = super::otp::totp(&seed, "plus", 60, 6, 1700000000);
            if c == "709288" {
                CheckResult { ok: true, detail: "öz-test geçti (709288)".into() }
            } else {
                CheckResult { ok: false, detail: format!("kripto uyumsuz ({c})") }
            }
        }
        _ => CheckResult { ok: false, detail: "bilinmeyen kontrol".into() },
    }
}
