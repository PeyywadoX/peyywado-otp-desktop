#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod capture;

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{LogicalSize, Manager, Size, State, WebviewUrl, WebviewWindowBuilder};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct Account {
    id: String,
    label: String,
    #[serde(default)]
    real_id: String,
    #[serde(default)]
    note: String,
    seed: String,
    kind: String,
    #[serde(default = "def_period")]
    period: u32,
    #[serde(default = "def_digits")]
    digits: u32,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    color: String,
}
fn def_period() -> u32 { 60 }
fn def_digits() -> u32 { 6 }

struct WindowRestoreState {
    prev_size: Mutex<Option<(f64, f64)>>,
}

fn gen_id() -> String {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("a{:x}", n)
}

fn vault_path() -> PathBuf {
    let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(base).join("PeyywadoOTP");
    let _ = fs::create_dir_all(&dir);
    dir.join("vault.dat")
}

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out,
        );
        if ok == 0 {
            return Err("DPAPI şifreleme başarısız".into());
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Ok(v)
    }
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out,
        );
        if ok == 0 {
            return Err("DPAPI çözme başarısız".into());
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Ok(v)
    }
}

#[cfg(not(windows))]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> { Ok(data.to_vec()) }
#[cfg(not(windows))]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> { Ok(data.to_vec()) }

fn vault_read() -> Vec<Account> {
    let p = vault_path();
    let Ok(enc) = fs::read(&p) else { return vec![] };
    let Ok(plain) = dpapi_unprotect(&enc) else { return vec![] };
    serde_json::from_slice(&plain).unwrap_or_default()
}

fn vault_write(accs: &[Account]) -> Result<(), String> {
    let plain = serde_json::to_vec(accs).map_err(|e| e.to_string())?;
    let enc = dpapi_protect(&plain)?;
    let path = vault_path();
    let tmp = path.with_extension("dat.tmp");
    fs::write(&tmp, &enc).map_err(|e| e.to_string())?;
    if fs::rename(&tmp, &path).is_err() {

        let _ = fs::remove_file(&path);
        fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn reorder_accounts(mut accs: Vec<Account>, ids: &[String]) -> Vec<Account> {
    let mut out = Vec::with_capacity(accs.len());
    for id in ids {
        if let Some(pos) = accs.iter().position(|a| &a.id == id) {
            out.push(accs.remove(pos));
        }
    }
    out.extend(accs);
    out
}

#[tauri::command]
fn vault_list() -> Vec<Account> {
    vault_read()
}

#[tauri::command]
fn vault_save(account: Account) -> Result<Account, String> {
    let mut accs = vault_read();
    let mut a = account;
    if a.id.is_empty() {
        a.id = gen_id();
    }
    if let Some(ex) = accs.iter_mut().find(|x| x.id == a.id) {
        *ex = a.clone();
    } else {
        accs.push(a.clone());
    }
    vault_write(&accs)?;
    Ok(a)
}

#[tauri::command]
fn vault_delete(id: String) -> Result<(), String> {
    let mut accs = vault_read();
    accs.retain(|x| x.id != id);
    vault_write(&accs)
}

#[tauri::command]
fn vault_reorder(ids: Vec<String>) -> Result<Vec<Account>, String> {
    let accs = vault_read();
    let reordered = reorder_accounts(accs, &ids);
    vault_write(&reordered)?;
    Ok(reordered)
}

#[tauri::command]
fn vault_info() -> serde_json::Value {
    let p = vault_path();
    let exists = p.exists();
    let bytes = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
    let count = vault_read().len();
    serde_json::json!({
        "path": p.to_string_lossy(),
        "exists": exists,
        "bytes": bytes,
        "count": count,
        "encryption": if cfg!(windows) { "Windows DPAPI (Kullanıcı Anahtarı)" } else { "Yerel Depolama" }
    })
}

#[tauri::command]
fn vault_export(ids: Vec<String>) -> Result<String, String> {
    let accs = vault_read();
    let list: Vec<&Account> = if ids.is_empty() {
        accs.iter().collect()
    } else {
        accs.iter().filter(|a| ids.contains(&a.id)).collect()
    };
    let payload = serde_json::json!({
        "app": "Peyywado OTP",
        "version": 2,
        "accounts": list.iter().map(|a| serde_json::json!({
            "label": a.label, "realId": a.real_id, "note": a.note,
            "seed": a.seed, "kind": a.kind, "period": a.period, "digits": a.digits,
            "pinned": a.pinned, "tag": a.tag, "color": a.color
        })).collect::<Vec<_>>()
    });
    serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())
}

#[tauri::command]
fn activate(otp_id: String, code: String, note: String, tag: Option<String>, color: Option<String>) -> Result<Account, String> {
    let d = otpcore::activate(&otp_id, &code, None, 10)?;
    let label = if note.trim().is_empty() {
        if d.serial.is_empty() { otp_id.clone() } else { d.serial.clone() }
    } else {
        note.clone()
    };
    let acc = Account {
        id: gen_id(),
        label,
        real_id: otp_id,
        note,
        seed: d.seed,
        kind: d.kind,
        period: d.period,
        digits: d.digits,
        pinned: false,
        tag: tag.unwrap_or_default(),
        color: color.unwrap_or_default(),
    };
    let mut accs = vault_read();
    accs.push(acc.clone());
    vault_write(&accs)?;
    Ok(acc)
}

#[tauri::command]
fn check_one(key: String) -> otpcore::CheckResult {
    otpcore::check_one(&key)
}

#[tauri::command]
fn sync_time() -> Result<otpcore::SyncResult, String> {
    otpcore::sync_time()
}

#[tauri::command]
fn win_minimize(window: tauri::Window) -> Result<(), String> {
    window.minimize().map_err(|e| e.to_string())
}

#[tauri::command]
fn win_toggle_maximize(window: tauri::Window) -> Result<bool, String> {
    let is_max = window.is_maximized().map_err(|e| e.to_string())?;
    if is_max {
        window.unmaximize().map_err(|e| e.to_string())?;
        Ok(false)
    } else {
        window.maximize().map_err(|e| e.to_string())?;
        Ok(true)
    }
}

#[tauri::command]
fn win_is_maximized(window: tauri::Window) -> Result<bool, String> {
    window.is_maximized().map_err(|e| e.to_string())
}

#[tauri::command]
fn win_close(window: tauri::Window) -> Result<(), String> {
    window.close().map_err(|e| e.to_string())
}

#[tauri::command]
fn win_set_always_on_top(window: tauri::Window, on: bool) -> Result<bool, String> {
    window.set_always_on_top(on).map_err(|e| e.to_string())?;
    Ok(on)
}

#[tauri::command]
fn win_set_mini_mode(
    window: tauri::Window,
    state: State<'_, WindowRestoreState>,
    mini: bool,
) -> Result<bool, String> {
    if mini {
        if window.is_maximized().unwrap_or(false) {
            let _ = window.unmaximize();
        }
        if let Ok(phys) = window.inner_size() {
            let sf = window.scale_factor().unwrap_or(1.0);
            let mut guard = state.prev_size.lock().unwrap();
            *guard = Some((phys.width as f64 / sf, phys.height as f64 / sf));
        }
        let _ = window.set_size(Size::Logical(LogicalSize { width: 360.0, height: 460.0 }));
        let _ = window.set_always_on_top(true);
        Ok(true)
    } else {
        let (w, h) = state
            .prev_size
            .lock()
            .unwrap()
            .take()
            .unwrap_or((430.0, 760.0));
        let _ = window.set_size(Size::Logical(LogicalSize {
            width: w.max(380.0),
            height: h.max(580.0),
        }));
        Ok(false)
    }
}

#[tauri::command]
fn win_start_drag(window: tauri::Window) -> Result<(), String> {
    window.start_dragging().map_err(|e| e.to_string())
}

#[tauri::command]
fn capture_list_ips() -> Vec<String> {
    capture::detect_lan_ips()
}

#[tauri::command]
fn capture_list_adapters() -> Vec<capture::LanAdapter> {
    capture::detect_lan_adapters()
}

#[tauri::command]
fn capture_start(
    app: tauri::AppHandle,
    state: State<'_, capture::CaptureManager>,
    preferred_ip: Option<String>,
    mode: Option<String>,
) -> Result<capture::CaptureSessionInfo, String> {
    state.start(app, preferred_ip, mode.unwrap_or_else(|| "proxy".into()))
}

#[tauri::command]
fn capture_stop(state: State<'_, capture::CaptureManager>) {
    state.stop();
}

#[tauri::command]
fn capture_status(state: State<'_, capture::CaptureManager>) -> Option<capture::CaptureSessionInfo> {
    state.status()
}

#[tauri::command]
fn decode_keydown_manual(header_hex: String, data_hex: String) -> Result<otpcore::KeydownResult, String> {
    otpcore::decode_keydown(&header_hex, &data_hex)
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    if !matches!(
        url.as_str(),
        "https://peyywado.com" | "https://peyywado.com/" | "https://wa.me/995599891235"
    ) {
        return Err("İzin verilmeyen bağlantı".into());
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let mut op: Vec<u16> = "open".encode_utf16().collect();
        op.push(0);
        let mut target: Vec<u16> = url.encode_utf16().collect();
        target.push(0);
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                op.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn dpapi_roundtrip() {
        let secret = b"peyywado-seed-0123456789ABCDEF";
        let enc = dpapi_protect(secret).expect("protect");
        assert_ne!(enc.as_slice(), secret, "şifreli veri düz metinden farklı olmalı");
        let dec = dpapi_unprotect(&enc).expect("unprotect");
        assert_eq!(dec.as_slice(), secret, "DPAPI çözümü orijinali vermeli");
    }

    #[test]
    fn vault_serde_roundtrip() {
        let a = Account {
            id: "a1".into(), label: "Knight".into(), real_id: "NT00KO123".into(),
            note: "ana".into(), seed: "11".repeat(32), kind: "plus".into(),
            period: 60, digits: 6, pinned: true, tag: "Ana".into(), color: "ember".into(),
        };
        let j = serde_json::to_string(&a).unwrap();
        assert!(j.contains("\"realId\""), "camelCase realId bekleniyor");
        let b: Account = serde_json::from_str(&j).unwrap();
        assert_eq!(b.seed, a.seed);
        assert!(b.pinned);
        assert_eq!(b.tag, "Ana");
    }

    #[test]
    fn legacy_v1_account_deserializes() {
        let legacy = r#"{"id":"a1","label":"KO","realId":"NT00","note":"","seed":"1111","kind":"plus","period":60,"digits":6}"#;
        let a: Account = serde_json::from_str(legacy).unwrap();
        assert!(!a.pinned);
        assert_eq!(a.tag, "");
        assert_eq!(a.color, "");
    }

    #[test]
    fn reorder_preserves_all_accounts() {
        let mk = |id: &str| Account {
            id: id.into(), label: id.into(), real_id: "".into(), note: "".into(),
            seed: "11".into(), kind: "plus".into(), period: 60, digits: 6,
            pinned: false, tag: "".into(), color: "".into(),
        };
        let list = vec![mk("a"), mk("b"), mk("c")];
        let out = reorder_accounts(list, &["c".into(), "a".into()]);
        let ids: Vec<&str> = out.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "a", "b"]);
    }
}

fn log_startup_error(msg: &str) {
    let p = std::env::temp_dir().join("PeyywadoOTP_error.log");
    let _ = fs::write(p, msg);
}

#[cfg(windows)]
fn show_startup_error(msg: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    log_startup_error(msg);
    let mut title: Vec<u16> = "Peyywado OTP — Başlatma Hatası".encode_utf16().collect();
    title.push(0);
    let mut body: Vec<u16> = msg.encode_utf16().collect();
    body.push(0);
    unsafe {
        MessageBoxW(std::ptr::null_mut(), body.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
    }
}

#[cfg(windows)]
fn is_elevated_process() -> bool {
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(windows)]
fn is_webview2_installed() -> bool {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_READ, REG_SZ,
    };
    let subkeys = [
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
        (HKEY_CURRENT_USER, "Software\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
    ];
    let pv_name: Vec<u16> = "pv\0".encode_utf16().collect();
    for (root, sub) in subkeys {
        let mut wide: Vec<u16> = sub.encode_utf16().collect();
        wide.push(0);
        let mut hkey: HKEY = std::ptr::null_mut();
        let rc = unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_READ, &mut hkey) };
        if rc == 0 {
            let mut buf = [0u16; 128];
            let mut buf_bytes = (buf.len() * 2) as u32;
            let mut val_type = 0u32;
            let qrc = unsafe {
                RegQueryValueExW(
                    hkey,
                    pv_name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    buf.as_mut_ptr() as *mut u8,
                    &mut buf_bytes,
                )
            };
            unsafe { RegCloseKey(hkey) };
            if qrc == 0 && val_type == REG_SZ && buf_bytes >= 2 {
                let len = (buf_bytes as usize / 2).min(buf.len());
                let ver = String::from_utf16_lossy(&buf[..len])
                    .trim_end_matches('\0')
                    .trim()
                    .to_string();
                if !ver.is_empty() && ver != "0.0.0.0" {
                    return true;
                }
            }
        }
    }
    for base in [
        r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application",
        r"C:\Program Files\Microsoft\EdgeWebView\Application",
    ] {
        if let Ok(entries) = fs::read_dir(base) {
            for ent in entries.flatten() {
                if ent.path().join("msedgewebview2.exe").exists() {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(windows)]
fn prompt_install_webview2() {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_ICONWARNING, MB_YESNO, SW_SHOWNORMAL,
    };
    let mut title: Vec<u16> = "Peyywado OTP — WebView2 Gerekli".encode_utf16().collect();
    title.push(0);
    let mut body: Vec<u16> = "Bu bilgisayarda Microsoft Edge WebView2 Runtime kurulu değil (Windows 10 LTSC / hafif Windows sürümlerinde ayrıca kurulması gerekir).\n\nMicrosoft'un resmi WebView2 indirme bağlantısı şimdi açılsın mı?".encode_utf16().collect();
    body.push(0);
    let ans = unsafe {
        MessageBoxW(std::ptr::null_mut(), body.as_ptr(), title.as_ptr(), MB_YESNO | MB_ICONWARNING)
    };
    if ans == IDYES {
        let mut op: Vec<u16> = "open".encode_utf16().collect();
        op.push(0);
        let mut url: Vec<u16> = "https://go.microsoft.com/fwlink/p/?LinkId=2124703".encode_utf16().collect();
        url.push(0);
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                op.as_ptr(),
                url.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
    }
}

#[cfg(not(windows))]
fn show_startup_error(msg: &str) {
    log_startup_error(msg);
    eprintln!("Peyywado OTP başlatma hatası: {msg}");
}
#[cfg(not(windows))]
fn is_elevated_process() -> bool { false }
#[cfg(not(windows))]
fn is_webview2_installed() -> bool { true }
#[cfg(not(windows))]
fn prompt_install_webview2() {}

#[cfg(windows)]
struct SingleInstanceGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,

    use_isolated_dir: bool,
}

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(windows)]
fn acquire_single_instance() -> Option<SingleInstanceGuard> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE,
    };

    let mut mutex_name: Vec<u16> = "Local\\PeyywadoOTP_SingleInstance_v2".encode_utf16().collect();
    mutex_name.push(0);
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr()) };
    if handle.is_null() {
        return Some(SingleInstanceGuard {
            handle,
            use_isolated_dir: false,
        });
    }

    let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if already {
        let mut title: Vec<u16> = "Peyywado OTP".encode_utf16().collect();
        title.push(0);
        for _ in 0..4 {
            let hwnd = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
            if !hwnd.is_null() {
                unsafe {
                    ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);
                }
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(handle);
                }
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(120));
        }

        return Some(SingleInstanceGuard {
            handle,
            use_isolated_dir: true,
        });
    }

    Some(SingleInstanceGuard {
        handle,
        use_isolated_dir: false,
    })
}

#[cfg(not(windows))]
struct SingleInstanceGuard {
    use_isolated_dir: bool,
}

#[cfg(not(windows))]
fn acquire_single_instance() -> Option<SingleInstanceGuard> {
    Some(SingleInstanceGuard {
        use_isolated_dir: false,
    })
}

fn webview_data_dir(suffix: &str) -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("TEMP"))
        .unwrap_or_else(|_| ".".into());

    let role = if is_elevated_process() { "wv2-admin" } else { "wv2-user" };
    let sub = if suffix.is_empty() {
        role.to_string()
    } else {
        format!("{role}-{suffix}")
    };
    let dir = PathBuf::from(base).join("PeyywadoOTP").join(sub);
    let _ = fs::create_dir_all(&dir);
    dir
}

fn build_main_window(
    app: &tauri::AppHandle,
    data_dir: PathBuf,
    extra_args: Option<&str>,
) -> Result<tauri::WebviewWindow, String> {
    let mut builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Peyywado OTP")
        .inner_size(430.0, 760.0)
        .min_inner_size(360.0, 560.0)
        .resizable(true)
        .decorations(false)
        .shadow(true)
        .center()
        .visible(true)
        .focused(true)
        .background_color(tauri::window::Color(7, 9, 14, 255))
        .data_directory(data_dir);
    #[cfg(windows)]
    if let Some(args) = extra_args {
        builder = builder.additional_browser_args(args);
    }
    let w = builder.build().map_err(|e| e.to_string())?;
    let _ = w.center();
    let _ = w.unminimize();
    let _ = w.show();
    let _ = w.set_focus();
    Ok(w)
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        show_startup_error(&format!(
            "Peyywado OTP beklenmeyen bir hatayla karşılaştı:\n\n{info}\n\nDetaylı günlük: %TEMP%\\PeyywadoOTP_error.log"
        ));
    }));

    if !is_webview2_installed() {
        prompt_install_webview2();
        return;
    }

    let Some(_instance_guard) = acquire_single_instance() else {
        return;
    };
    let use_isolated = _instance_guard.use_isolated_dir;

    let res = tauri::Builder::default()
        .manage(WindowRestoreState {
            prev_size: Mutex::new(None),
        })
        .manage(capture::CaptureManager::default())
        .setup(move |app| {
            let handle = app.handle();
            let pid_suffix = format!("p{}", std::process::id());
            let primary_dir = if use_isolated {
                webview_data_dir(&pid_suffix)
            } else {
                webview_data_dir("")
            };

            if let Err(err1) = build_main_window(handle, primary_dir, None) {
                let nogpu_dir = webview_data_dir("nogpu");
                if let Err(err2) =
                    build_main_window(handle, nogpu_dir, Some("--disable-gpu --disable-gpu-compositing"))
                {
                    let iso_dir = webview_data_dir(&pid_suffix);
                    if let Err(err3) =
                        build_main_window(handle, iso_dir, Some("--disable-gpu --disable-gpu-compositing"))
                    {
                        show_startup_error(&format!(
                            "Peyywado OTP penceresi oluşturulamadı.\n\nİlk hata: {err1}\nGPU kapalı hata: {err2}\nİzole klasör hata: {err3}\n\nNot: Microsoft Edge WebView2 Runtime'ı güncelleyin."
                        ));
                        return Err(err3.into());
                    }
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed) {
                window.state::<capture::CaptureManager>().stop();
                if matches!(event, tauri::WindowEvent::Destroyed) {
                    window.app_handle().exit(0);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            vault_list,
            vault_save,
            vault_delete,
            vault_reorder,
            vault_info,
            vault_export,
            activate,
            check_one,
            sync_time,
            win_minimize,
            win_toggle_maximize,
            win_is_maximized,
            win_close,
            win_set_always_on_top,
            win_set_mini_mode,
            win_start_drag,
            capture_list_ips,
            capture_list_adapters,
            capture_start,
            capture_stop,
            capture_status,
            decode_keydown_manual,
            open_external_url
        ])
        .run(tauri::generate_context!());

    if let Err(e) = res {
        show_startup_error(&format!(
            "Peyywado OTP başlatılamadı.\n\nDetay: {e}\n\nWindows'ta Microsoft Edge WebView2 Runtime kurulu olduğundan emin olun."
        ));
    }
}
