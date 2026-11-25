use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use flate2::read::GzDecoder;
use otpcore::keydown::{parse_keydown_response, KeydownResult};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

const TARGET_HOST: &str = "otpservice.nttgame.com";
const TARGET_PORT: u16 = 443;
const SELF_TEST_PATH: &str = "/__peyywado_test";
const MAX_CONCURRENT_CONNS: usize = 128;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanAdapter {
    pub ip: String,
    pub name: String,
    pub recommended: bool,
}

struct WorkerGuard(Arc<AtomicUsize>);
impl WorkerGuard {
    fn try_acquire(counter: &Arc<AtomicUsize>) -> Option<Self> {
        let prev = counter.fetch_add(1, Ordering::SeqCst);
        if prev >= MAX_CONCURRENT_CONNS {
            counter.fetch_sub(1, Ordering::SeqCst);
            None
        } else {
            Some(Self(counter.clone()))
        }
    }
}
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureSessionInfo {
    pub active: bool,
    pub mode: String,
    pub lan_ip: String,
    pub proxy_port: u16,
    pub qr_url: String,
    pub pac_url: String,
    pub cert_url: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureEvent {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<KeydownResult>,
}

struct ActiveSession {
    stop: Arc<AtomicBool>,
    info: CaptureSessionInfo,
    dns_bind_ip: Option<Ipv4Addr>,
    handles: Vec<JoinHandle<()>>,
}

pub struct CaptureManager {
    inner: Mutex<Option<ActiveSession>>,
}

impl Default for CaptureManager {
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

impl CaptureManager {
    pub fn status(&self) -> Option<CaptureSessionInfo> {
        let guard = self.inner.lock().unwrap();
        guard.as_ref().map(|s| s.info.clone())
    }

    pub fn stop(&self) {
        let sess = {
            let mut guard = self.inner.lock().unwrap();
            guard.take()
        };
        if let Some(sess) = sess {
            sess.stop.store(true, Ordering::SeqCst);

            let _ = TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], sess.info.proxy_port)),
                Duration::from_millis(80),
            );
            if sess.info.mode == "dns" {
                let _ = TcpStream::connect_timeout(
                    &SocketAddr::from(([127, 0, 0, 1], 443)),
                    Duration::from_millis(80),
                );
                if let Some(ip) = sess.dns_bind_ip {
                    if let Ok(u) = UdpSocket::bind("0.0.0.0:0") {
                        let _ = u.send_to(&[0u8], SocketAddr::new(IpAddr::V4(ip), 53));
                    }
                }
            }

            for h in sess.handles {
                let _ = h.join();
            }
        }
    }

    pub fn start(
        &self,
        app: AppHandle,
        preferred_ip: Option<String>,
        mode: String,
    ) -> Result<CaptureSessionInfo, String> {
        self.stop();

        let lan_ip = match preferred_ip
            .map(|s| s.trim().to_string())
            .filter(|s| s.parse::<Ipv4Addr>().is_ok())
        {
            Some(ip) => ip,
            None => detect_primary_lan_ip().ok_or_else(|| {
                "Yerel Wi-Fi/LAN IP adresi algılanamadı. Lütfen IP adresinizi elle girin."
                    .to_string()
            })?,
        };

        let mode_norm = if mode.eq_ignore_ascii_case("dns") {
            "dns".to_string()
        } else {
            "proxy".to_string()
        };

        let bundle = generate_ephemeral_bundle(&lan_ip)?;
        let server_tls = build_server_tls(&bundle)?;
        let client_tls = build_client_tls();

        let (http_listener, proxy_port) = bind_proxy_port()?;
        http_listener
            .set_nonblocking(true)
            .map_err(|e| format!("Soket ayarlanamadı: {e}"))?;

        let mut dns_bind_ip = None;
        let dns_sockets = if mode_norm == "dns" {
            let bind_ip: Ipv4Addr = lan_ip
                .parse()
                .map_err(|_| "Geçersiz IPv4 adresi".to_string())?;
            let udp = UdpSocket::bind(SocketAddr::new(IpAddr::V4(bind_ip), 53)).map_err(|e| {
                format!(
                    "DNS modu için UDP 53 portu açılamadı ({e}). Önerilen 'Proxy Modu'nu kullanın."
                )
            })?;
            udp.set_read_timeout(Some(Duration::from_millis(200)))
                .map_err(|e| e.to_string())?;

            let https = TcpListener::bind(("0.0.0.0", 443)).map_err(|e| {
                format!(
                    "DNS modu için TCP 443 portu açılamadı ({e}). Önerilen 'Proxy Modu'nu kullanın."
                )
            })?;
            https.set_nonblocking(true).map_err(|e| e.to_string())?;
            dns_bind_ip = Some(bind_ip);
            Some((udp, https, bind_ip))
        } else {
            None
        };

        let stop = Arc::new(AtomicBool::new(false));
        let info = CaptureSessionInfo {
            active: true,
            mode: mode_norm.clone(),
            lan_ip: lan_ip.clone(),
            proxy_port,
            qr_url: format!("http://{}:{}/", lan_ip, proxy_port),
            pac_url: format!("http://{}:{}/proxy.pac", lan_ip, proxy_port),
            cert_url: format!("http://{}:{}/ca.mobileconfig", lan_ip, proxy_port),
        };

        let ctx = Arc::new(RuntimeCtx {
            app: app.clone(),
            stop: stop.clone(),
            active_conns: Arc::new(AtomicUsize::new(0)),
            lan_ip: lan_ip.clone(),
            proxy_port,
            mode: mode_norm.clone(),
            mobileconfig: bundle.mobileconfig_xml,
            server_tls,
            client_tls,
        });

        let mut handles = Vec::new();

        {
            let ctx_c = ctx.clone();
            handles.push(thread::spawn(move || {
                while !ctx_c.stop.load(Ordering::SeqCst) {
                    match http_listener.accept() {
                        Ok((stream, addr)) => {
                            if ctx_c.stop.load(Ordering::SeqCst) {
                                break;
                            }
                            if let Some(guard) = WorkerGuard::try_acquire(&ctx_c.active_conns) {
                                let c = ctx_c.clone();
                                thread::spawn(move || {
                                    let _g = guard;
                                    handle_http_or_proxy(stream, addr, c);
                                });
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(35));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            }));
        }

        if let Some((udp, https, redirect_ip)) = dns_sockets {
            let ctx_dns = ctx.clone();
            handles.push(thread::spawn(move || run_dns_loop(udp, redirect_ip, ctx_dns)));

            let ctx_443 = ctx.clone();
            handles.push(thread::spawn(move || {
                while !ctx_443.stop.load(Ordering::SeqCst) {
                    match https.accept() {
                        Ok((stream, addr)) => {
                            if ctx_443.stop.load(Ordering::SeqCst) {
                                break;
                            }
                            if let Some(guard) = WorkerGuard::try_acquire(&ctx_443.active_conns) {
                                let c = ctx_443.clone();
                                thread::spawn(move || {
                                    let _g = guard;
                                    handle_mitm_tls(stream, addr, c);
                                });
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(35));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            }));
        }

        {
            let mut guard = self.inner.lock().unwrap();
            *guard = Some(ActiveSession {
                stop,
                info: info.clone(),
                dns_bind_ip,
                handles,
            });
        }

        emit(
            &app,
            "started",
            format!(
                "Yakalayıcı hazır ({}:{} — {})",
                info.lan_ip,
                info.proxy_port,
                if info.mode == "dns" {
                    "DNS Modu"
                } else {
                    "Proxy Modu"
                }
            ),
            None,
            None,
        );

        Ok(info)
    }
}

struct RuntimeCtx {
    app: AppHandle,
    stop: Arc<AtomicBool>,
    active_conns: Arc<AtomicUsize>,
    lan_ip: String,
    proxy_port: u16,
    mode: String,
    mobileconfig: String,
    server_tls: Arc<ServerConfig>,
    client_tls: Arc<ClientConfig>,
}

fn emit(
    app: &AppHandle,
    kind: &str,
    message: impl Into<String>,
    client_ip: Option<String>,
    result: Option<KeydownResult>,
) {
    let _ = app.emit(
        "capture-event",
        CaptureEvent {
            kind: kind.to_string(),
            message: message.into(),
            client_ip,
            result,
        },
    );
}

fn is_virtual_adapter_name(name: &str, desc: &str) -> bool {
    let hay = format!("{} {}", name, desc).to_ascii_lowercase();
    [
        "hyper-v",
        "hyperv",
        "vethernet",
        "vmware",
        "virtualbox",
        "vbox",
        "wsl",
        "loopback",
        "tap-",
        "wintun",
        "tunnel",
        "utun",
        "tun0",
        "tun1",
        "tun-",
        "wireguard",
        "zerotier",
        "hamachi",
        "nordlynx",
        "tailscale",
        "cloudflare",
        "warp",
        "openvpn",
        "mullvad",
        "proton",
        "anyconnect",
        "fortinet",
        "globalprotect",
        "pulse secure",
        "radmin",
        "bluetooth",
        "npcap",
        "bluestacks",
        "ldplayer",
        "memu",
        "parallels",
        "qemu",
        "virtio",
        "wan miniport",
        "teredo",
        "isatap",
        "virtual",
        "docker",
    ]
    .iter()
    .any(|k| hay.contains(k))
}

fn lan_ip_bonus(ip_str: &str) -> u8 {
    let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
        return 3;
    };
    let o = ip.octets();
    if o[0] == 192 && o[1] == 168 {
        0
    } else if o[0] == 10 {
        1
    } else if o[0] == 172 && (16..=31).contains(&o[1]) {
        2
    } else {
        3
    }
}

#[cfg(windows)]
unsafe fn pwstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < 512 && *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

#[cfg(windows)]
fn detect_windows_adapters() -> Vec<(u8, u8, LanAdapter)> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16384;
    let mut buf: Vec<u8> = vec![0u8; size as usize];
    let mut rc = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        )
    };
    if rc == ERROR_BUFFER_OVERFLOW && size > 0 && size < 4 * 1024 * 1024 {
        buf.resize(size as usize, 0);
        rc = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
    }
    if rc != 0 {
        return Vec::new();
    }

    let mut out: Vec<(u8, u8, LanAdapter)> = Vec::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        let a = unsafe { &*cur };
        if a.OperStatus == IfOperStatusUp {
            let fname = unsafe { pwstr_to_string(a.FriendlyName) };
            let desc = unsafe { pwstr_to_string(a.Description) };
            let is_virt = is_virtual_adapter_name(&fname, &desc);
            let is_wifi = a.IfType == 71;
            let is_eth = a.IfType == 6;

            let mut has_gateway = false;
            let mut gw = a.FirstGatewayAddress;
            while !gw.is_null() {
                let gw_rec = unsafe { &*gw };
                let gsa = gw_rec.Address.lpSockaddr;
                if !gsa.is_null() && unsafe { (*gsa).sa_family } == AF_INET {
                    let gsin = unsafe { &*(gsa as *const SOCKADDR_IN) };
                    let gip = Ipv4Addr::from(unsafe { gsin.sin_addr.S_un.S_addr }.to_ne_bytes());
                    if !gip.is_unspecified() && !gip.is_loopback() {
                        has_gateway = true;
                        break;
                    }
                }
                gw = gw_rec.Next;
            }

            let mut ua = a.FirstUnicastAddress;
            while !ua.is_null() {
                let addr_rec = unsafe { &*ua };
                let sa = addr_rec.Address.lpSockaddr;
                if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET {
                    let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                    let bytes = unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes();
                    let ip = Ipv4Addr::from(bytes);
                    if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() {
                        let ip_str = ip.to_string();
                        let prio: u8 = if !is_virt && has_gateway && (is_wifi || is_eth) {
                            0
                        } else if !is_virt && has_gateway {
                            1
                        } else if !is_virt && (is_wifi || is_eth) {
                            2
                        } else if !is_virt {
                            3
                        } else {
                            5
                        };
                        let media_tie: u8 = if is_wifi { 0 } else if is_eth { 1 } else { 2 };
                        let label = if fname.is_empty() { desc.clone() } else { fname.clone() };
                        if !out.iter().any(|(_, _, x)| x.ip == ip_str) {
                            out.push((
                                prio,
                                media_tie,
                                LanAdapter {
                                    ip: ip_str,
                                    name: label,
                                    recommended: prio <= 1,
                                },
                            ));
                        }
                    }
                }
                ua = addr_rec.Next;
            }
        }
        cur = a.Next;
    }
    out
}

fn detect_active_outbound_ip() -> Option<String> {
    for probe in ["1.1.1.1:80", "8.8.8.8:80"] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(probe).is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    if let IpAddr::V4(v4) = addr.ip() {
                        if !v4.is_loopback() && !v4.is_unspecified() && !v4.is_link_local() {
                            return Some(v4.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn detect_lan_adapters() -> Vec<LanAdapter> {
    #[cfg(windows)]
    let mut ranked = detect_windows_adapters();
    #[cfg(not(windows))]
    let mut ranked: Vec<(u8, u8, LanAdapter)> = Vec::new();

    let active_route_ip = detect_active_outbound_ip();

    for probe in [
        "1.1.1.1:80",
        "8.8.8.8:80",
        "192.168.1.1:80",
        "192.168.0.1:80",
        "192.168.2.1:80",
        "10.0.0.1:80",
    ] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(probe).is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    if let IpAddr::V4(v4) = addr.ip() {
                        if !v4.is_loopback() && !v4.is_unspecified() && !v4.is_link_local() {
                            let s = v4.to_string();
                            if !ranked.iter().any(|(_, _, a)| a.ip == s) {
                                let prio = if lan_ip_bonus(&s) <= 2 { 2 } else { 4 };
                                ranked.push((
                                    prio,
                                    2,
                                    LanAdapter {
                                        ip: s,
                                        name: "Yerel Ağ".into(),
                                        recommended: prio <= 2,
                                    },
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    ranked.sort_by_key(|(prio, media_tie, a)| {

        let route_rank: u8 = if *prio < 5 && active_route_ip.as_deref() == Some(a.ip.as_str()) {
            0
        } else {
            1
        };
        (*prio, route_rank, *media_tie, lan_ip_bonus(&a.ip))
    });

    ranked.into_iter().map(|(_, _, a)| a).collect()
}

pub fn detect_primary_lan_ip() -> Option<String> {
    detect_lan_adapters().into_iter().next().map(|a| a.ip)
}

pub fn detect_lan_ips() -> Vec<String> {
    detect_lan_adapters().into_iter().map(|a| a.ip).collect()
}

fn bind_proxy_port() -> Result<(TcpListener, u16), String> {
    for port in 8888..=8898 {
        if let Ok(l) = TcpListener::bind(("0.0.0.0", port)) {
            return Ok((l, port));
        }
    }
    Err("8888-8898 portları kullanımda. Lütfen çakışan uygulamayı kapatın.".into())
}

struct EphemeralBundle {
    leaf_der: Vec<u8>,
    leaf_key_der: Vec<u8>,
    ca_der: Vec<u8>,
    mobileconfig_xml: String,
}

fn generate_ephemeral_bundle(lan_ip: &str) -> Result<EphemeralBundle, String> {
    let now = SystemTime::now();
    let not_before = now - Duration::from_secs(3600 * 24);
    let not_after = now + Duration::from_secs(3600 * 24 * 30);

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Peyywado OTP Gecici CA");
    ca_dn.push(DnType::OrganizationName, "Peyywado OTP");
    ca_params.distinguished_name = ca_dn;
    ca_params.not_before = not_before.into();
    ca_params.not_after = not_after.into();

    let ca_key = KeyPair::generate().map_err(|e| format!("CA anahtarı üretilemedi: {e}"))?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| format!("CA sertifikası üretilemedi: {e}"))?;

    let mut leaf_params = CertificateParams::default();
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, TARGET_HOST);
    leaf_dn.push(DnType::OrganizationName, "Peyywado OTP Local");
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.not_before = not_before.into();
    leaf_params.not_after = not_after.into();

    let mut sans = vec![
        SanType::DnsName(TARGET_HOST.try_into().map_err(|_| "geçersiz SAN")?),
        SanType::DnsName("otpsvr.nttgame.com".try_into().map_err(|_| "geçersiz SAN")?),
        SanType::DnsName("otpsvr2.nttgame.com".try_into().map_err(|_| "geçersiz SAN")?),
        SanType::DnsName("otp.nttgame.com".try_into().map_err(|_| "geçersiz SAN")?),
    ];
    if let Ok(ip) = lan_ip.parse::<IpAddr>() {
        sans.push(SanType::IpAddress(ip));
    }
    leaf_params.subject_alt_names = sans;

    let leaf_key = KeyPair::generate().map_err(|e| format!("Yaprak anahtar üretilemedi: {e}"))?;
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|e| format!("Yaprak sertifika imzalanamadı: {e}"))?;

    let ca_der = ca_cert.der().to_vec();
    let leaf_der = leaf_cert.der().to_vec();
    let leaf_key_der = leaf_key.serialize_der();

    let b64_ca = B64.encode(&ca_der);
    let payload_uuid = Uuid::new_v4().to_string().to_uppercase();
    let root_uuid = Uuid::new_v4().to_string().to_uppercase();

    let mobileconfig_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadContent</key><array><dict>
    <key>PayloadCertificateFileName</key><string>peyywado-otp-ca.cer</string>
    <key>PayloadContent</key><data>{b64_ca}</data>
    <key>PayloadDescription</key><string>AnyOTP+ seed yakalama icin yerel gecici sertifika. Islem bitince Ayarlar'dan kaldirabilirsiniz.</string>
    <key>PayloadDisplayName</key><string>Peyywado OTP Gecici CA</string>
    <key>PayloadIdentifier</key><string>com.peyywado.otp.capture.ca</string>
    <key>PayloadType</key><string>com.apple.security.root</string>
    <key>PayloadUUID</key><string>{payload_uuid}</string>
    <key>PayloadVersion</key><integer>1</integer>
  </dict></array>
  <key>PayloadDescription</key><string>Peyywado OTP yerel seed yakalama profili. Yalnizca bu oturum icin uretilmistir.</string>
  <key>PayloadDisplayName</key><string>Peyywado OTP (Gecici)</string>
  <key>PayloadIdentifier</key><string>com.peyywado.otp.capture</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{root_uuid}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#
    );

    Ok(EphemeralBundle {
        leaf_der,
        leaf_key_der,
        ca_der,
        mobileconfig_xml,
    })
}

fn build_server_tls(bundle: &EphemeralBundle) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let chain = vec![
        CertificateDer::from(bundle.leaf_der.clone()),
        CertificateDer::from(bundle.ca_der.clone()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bundle.leaf_key_der.clone()));

    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS sunucu sürüm hatası: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("TLS sertifika yüklenemedi: {e}"))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn build_client_tls() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls client versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

fn read_raw_http_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    while buf.len() < 32768 {
        match stream.read(&mut b) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {
                buf.push(b[0]);
                if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                    return Some(buf);
                }
            }
        }
    }
    None
}

fn parse_absolute_http_uri(target: &str) -> Option<(String, u16, String)> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority, 80);
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_string()))
}

fn is_self_host(host: &str, port: u16, ctx: &RuntimeCtx) -> bool {
    port == ctx.proxy_port
        && (host == ctx.lan_ip
            || host == "127.0.0.1"
            || host.eq_ignore_ascii_case("localhost"))
}

fn handle_http_or_proxy(mut stream: TcpStream, addr: SocketAddr, ctx: Arc<RuntimeCtx>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let Some(head_raw) = read_raw_http_head(&mut stream) else {
        return;
    };
    let head_str = String::from_utf8_lossy(&head_raw);
    let mut lines = head_str.split("\r\n");
    let Some(first_line) = lines.next() else {
        return;
    };
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let target = parts[1];

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    let mut expect_100 = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if kl == "content-length" {
                content_length = val.parse().unwrap_or(0);
            } else if kl == "expect" && val.to_ascii_lowercase().contains("100-continue") {
                expect_100 = true;
            }
            headers.push((k.trim().to_string(), val));
        }
    }

    let peer_ip = addr.ip().to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, 443);

        if host.eq_ignore_ascii_case(TARGET_HOST) && port == 443 {

            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
                || stream.flush().is_err()
            {
                return;
            }
            handle_mitm_tls(stream, addr, ctx);
        } else {

            let Some(upstream) = connect_host_filtered(&host, port, &ctx.lan_ip, true) else {
                write_http(&mut stream, "502 Bad Gateway", "text/plain", b"Bad Gateway", None);
                return;
            };
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
                || stream.flush().is_err()
            {
                return;
            }
            tcp_passthrough(stream, upstream);
        }
        return;
    }

    if let Some((host, port, abs_path)) = parse_absolute_http_uri(target) {
        if !is_self_host(&host, port, &ctx) {
            if expect_100 {
                let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                let _ = stream.flush();
            }
            let mut body = vec![0u8; content_length.min(2 * 1024 * 1024)];
            if !body.is_empty() && stream.read_exact(&mut body).is_err() {
                return;
            }
            forward_plain_http(&mut stream, method, &host, port, &abs_path, &headers, &body, &ctx.lan_ip);
            return;
        }

        serve_local_endpoint(&mut stream, method, &abs_path, &peer_ip, &ctx);
        return;
    }

    serve_local_endpoint(&mut stream, method, target, &peer_ip, &ctx);
}

fn serve_local_endpoint(
    stream: &mut TcpStream,
    method: &str,
    target: &str,
    peer_ip: &str,
    ctx: &RuntimeCtx,
) {
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        write_http(stream, "405 Method Not Allowed", "text/plain", b"Method Not Allowed", None);
        return;
    }
    let path = target.split('?').next().unwrap_or(target);
    match path {
        "/" | "/index.html" => {
            emit(
                &ctx.app,
                "phone_connected",
                format!("iPhone bağlandı ({peer_ip}) — profil sayfası açıldı"),
                Some(peer_ip.to_string()),
                None,
            );
            let html = build_mobile_landing_html(&ctx.lan_ip, ctx.proxy_port, &ctx.mode);
            write_http(
                stream,
                "200 OK",
                "text/html; charset=utf-8",
                if method.eq_ignore_ascii_case("HEAD") { b"" } else { html.as_bytes() },
                None,
            );
        }
        "/ca.mobileconfig" => {
            emit(
                &ctx.app,
                "cert_downloaded",
                format!("Sertifika profili indirildi ({peer_ip})"),
                Some(peer_ip.to_string()),
                None,
            );
            write_http(
                stream,
                "200 OK",
                "application/x-apple-aspen-config",
                if method.eq_ignore_ascii_case("HEAD") { b"" } else { ctx.mobileconfig.as_bytes() },
                Some("attachment; filename=\"peyywado-otp-ca.mobileconfig\""),
            );
        }
        "/proxy.pac" | "/p.pac" => {
            emit(
                &ctx.app,
                "pac_fetched",
                format!("iPhone otomatik proxy (PAC) ayarını aldı ({peer_ip})"),
                Some(peer_ip.to_string()),
                None,
            );
            let pac = format!(
                "function FindProxyForURL(url, host) {{\n  if (host === \"{TARGET_HOST}\") return \"PROXY {}:{}\";\n  return \"DIRECT\";\n}}\n",
                ctx.lan_ip, ctx.proxy_port
            );
            write_http(
                stream,
                "200 OK",
                "application/x-ns-proxy-autoconfig",
                if method.eq_ignore_ascii_case("HEAD") { b"" } else { pac.as_bytes() },
                None,
            );
        }
        _ => {
            write_http(stream, "404 Not Found", "text/plain; charset=utf-8", b"Not Found", None);
        }
    }
}

fn forward_plain_http(
    client: &mut TcpStream,
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    lan_ip: &str,
) {
    let Some(mut up) = connect_host_filtered(host, port, lan_ip, false) else {
        write_http(client, "502 Bad Gateway", "text/plain", b"Bad Gateway", None);
        return;
    };
    let _ = up.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = up.set_write_timeout(Some(Duration::from_secs(15)));

    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    let mut has_host = false;
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if matches!(kl.as_str(), "proxy-connection" | "connection" | "expect") {
            continue;
        }
        if kl == "host" {
            has_host = true;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_host {
        if port == 80 {
            req.push_str(&format!("Host: {host}\r\n"));
        } else {
            req.push_str(&format!("Host: {host}:{port}\r\n"));
        }
    }
    req.push_str("Connection: close\r\n\r\n");
    if up.write_all(req.as_bytes()).is_err() {
        return;
    }
    if !body.is_empty() && up.write_all(body).is_err() {
        return;
    }
    let _ = up.flush();

    let mut tmp = [0u8; 8192];
    loop {
        match up.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if client.write_all(&tmp[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = client.flush();
}

fn write_http(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    disposition: Option<&str>,
) {
    let mut hdr = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(d) = disposition {
        hdr.push_str(&format!("Content-Disposition: {d}\r\n"));
    }
    hdr.push_str("\r\n");
    let _ = stream.write_all(hdr.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.trim_matches(['[', ']']).to_string(), port);
        }
    }
    (s.trim_matches(['[', ']']).to_string(), default_port)
}

fn filter_non_loop_addrs(addrs: Vec<SocketAddr>, lan_ip: &str) -> Vec<SocketAddr> {
    let self_v4 = lan_ip.parse::<IpAddr>().ok();
    addrs
        .into_iter()
        .filter(|a| !a.ip().is_loopback() && Some(a.ip()) != self_v4)
        .collect()
}

fn sort_ipv4_first(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.sort_by_key(|a| !a.is_ipv4());
    addrs
}

fn connect_host_filtered(
    host: &str,
    port: u16,
    lan_ip: &str,
    forbid_self: bool,
) -> Option<TcpStream> {
    let all: Vec<SocketAddr> = (host, port).to_socket_addrs().ok()?.collect();
    let addrs = sort_ipv4_first(if forbid_self {
        filter_non_loop_addrs(all, lan_ip)
    } else {
        all
    });
    for a in addrs {
        if let Ok(s) = TcpStream::connect_timeout(&a, Duration::from_secs(4)) {
            let _ = s.set_nodelay(true);
            return Some(s);
        }
    }
    None
}

fn tcp_passthrough(client: TcpStream, upstream: TcpStream) {
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(60)));

    let (Ok(mut c_rd), Ok(mut c_wr)) = (client.try_clone(), client.try_clone()) else {
        return;
    };
    let (Ok(mut u_rd), Ok(mut u_wr)) = (upstream.try_clone(), upstream.try_clone()) else {
        return;
    };

    let t1 = thread::spawn(move || {
        let _ = io::copy(&mut c_rd, &mut u_wr);
        let _ = u_wr.shutdown(std::net::Shutdown::Write);
    });
    let _ = io::copy(&mut u_rd, &mut c_wr);
    let _ = c_wr.shutdown(std::net::Shutdown::Write);
    let _ = t1.join();
}

fn handle_mitm_tls(stream: TcpStream, addr: SocketAddr, ctx: Arc<RuntimeCtx>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(25)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(25)));
    let peer_ip = addr.ip().to_string();

    let conn = match ServerConnection::new(ctx.server_tls.clone()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut tls = StreamOwned::new(conn, stream);

    if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
        emit(
            &ctx.app,
            "tls_error",
            format!("iPhone sertifikaya henüz güvenmedi ({e}). Ayarlar → Genel → Hakkında → Sertifika Güven Ayarları'ndan Tam Güven'i açın."),
            Some(peer_ip),
            None,
        );
        return;
    }

    emit(
        &ctx.app,
        "tls_ok",
        format!("Güvenli TLS bağlantısı doğrulandı ({peer_ip}) — aktivasyon dinleniyor"),
        Some(peer_ip.clone()),
        None,
    );

    for _ in 0..8 {
        let Some((first_line, headers, req_body)) = read_http_message(&mut tls) else {
            break;
        };
        let mut split = first_line.split_whitespace();
        let method = split.next().unwrap_or("GET");
        let path = split.next().unwrap_or("/");

        if path.starts_with(SELF_TEST_PATH) {
            let html = build_mobile_test_ok_html();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
                html.len(),
                html
            );
            let _ = tls.write_all(resp.as_bytes());
            let _ = tls.flush();
            break;
        }

        emit(
            &ctx.app,
            "request",
            format!("{method} {path}"),
            Some(peer_ip.clone()),
            None,
        );

        let resp_raw = match forward_to_upstream(
            method,
            path,
            &headers,
            &req_body,
            &ctx.client_tls,
            &ctx.lan_ip,
        ) {
            Ok(r) => r,
            Err(e) => {
                emit(
                    &ctx.app,
                    "warning",
                    format!("NTTGame sunucusuna iletilemedi: {e}"),
                    Some(peer_ip.clone()),
                    None,
                );
                break;
            }
        };

        if tls.write_all(&resp_raw).is_err() || tls.flush().is_err() {
            break;
        }

        if let Some(body) = extract_http_body(&resp_raw) {
            let is_keydown = path.to_ascii_lowercase().contains("keydown");
            match parse_keydown_response(&body) {
                Ok(Some(res)) => {
                    emit(
                        &ctx.app,
                        "seed_captured",
                        format!("SEED yakalandı: {} (Seri: {})", res.uid, res.serial),
                        Some(peer_ip.clone()),
                        Some(res),
                    );
                }
                Err(msg) if is_keydown => {
                    emit(
                        &ctx.app,
                        "activation_error",
                        msg,
                        Some(peer_ip.clone()),
                        None,
                    );
                }
                _ => {}
            }
        }

        if let Some(pos) = find_subslice(&resp_raw, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&resp_raw[..pos]).to_ascii_lowercase();
            let has_framing =
                head.contains("content-length:") || head.contains("transfer-encoding: chunked");
            if head.contains("connection: close") || !has_framing {
                break;
            }
        } else {
            break;
        }
    }

    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn read_http_message<S: Read + Write>(
    stream: &mut S,
) -> Option<(String, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 65536 {
            return None;
        }
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };

    let head_bytes = &buf[..header_end];
    let mut body = buf[header_end + 4..].to_vec();
    let head_str = String::from_utf8_lossy(head_bytes);
    let mut lines = head_str.split("\r\n");
    let first_line = lines.next()?.trim().to_string();
    if first_line.is_empty() {
        return None;
    }

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    let mut expect_100 = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if kl == "content-length" {
                content_length = val.parse().ok();
            } else if kl == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            } else if kl == "expect" && val.to_ascii_lowercase().contains("100-continue") {
                expect_100 = true;
            }
            headers.push((k.trim().to_string(), val));
        }
    }

    if expect_100 && body.is_empty() {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        let _ = stream.flush();
    }

    if let Some(cl) = content_length {
        while body.len() < cl && body.len() < 4 * 1024 * 1024 {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
            }
        }
        body.truncate(cl);
    } else if is_chunked {
        while find_subslice(&body, b"0\r\n\r\n").is_none() && body.len() < 4 * 1024 * 1024 {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
            }
        }
        body = dechunk(&body);
    }

    Some((first_line, headers, body))
}

fn forward_to_upstream(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    client_tls: &Arc<ClientConfig>,
    lan_ip: &str,
) -> Result<Vec<u8>, String> {
    let raw = connect_host_filtered(TARGET_HOST, TARGET_PORT, lan_ip, true).ok_or_else(|| {
        "Gerçek sunucuya bağlanılamadı (PC DNS'inin kendine dönmediğinden emin olun)".to_string()
    })?;
    let _ = raw.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = raw.set_write_timeout(Some(Duration::from_secs(20)));

    let server_name =
        ServerName::try_from(TARGET_HOST.to_string()).map_err(|_| "geçersiz SNI".to_string())?;
    let conn = ClientConnection::new(client_tls.clone(), server_name)
        .map_err(|e| format!("Upstream TLS başlatılamadı: {e}"))?;
    let mut up = StreamOwned::new(conn, raw);

    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if matches!(
            kl.as_str(),
            "host"
                | "accept-encoding"
                | "connection"
                | "content-length"
                | "transfer-encoding"
                | "proxy-connection"
                | "expect"
        ) {
            continue;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Host: {TARGET_HOST}\r\n"));
    req.push_str("Accept-Encoding: identity\r\n");
    req.push_str("Connection: close\r\n");
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");

    up.write_all(req.as_bytes())
        .map_err(|e| format!("İstek yazılamadı: {e}"))?;
    if !body.is_empty() {
        up.write_all(body)
            .map_err(|e| format!("İstek gövdesi yazılamadı: {e}"))?;
    }
    up.flush().map_err(|e| format!("Flush hatası: {e}"))?;

    let mut resp = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    loop {
        match up.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&tmp[..n]);
                if resp.len() > 4 * 1024 * 1024 {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(_) if !resp.is_empty() => break,
            Err(e) => return Err(format!("Yanıt okunamadı: {e}")),
        }
    }
    Ok(resp)
}

fn extract_http_body(raw: &[u8]) -> Option<Vec<u8>> {
    let pos = find_subslice(raw, b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..pos]).to_ascii_lowercase();
    let mut body = if head.contains("transfer-encoding: chunked") {
        dechunk(&raw[pos + 4..])
    } else {
        raw[pos + 4..].to_vec()
    };
    if head.contains("content-encoding: gzip") || (body.len() >= 2 && body[0] == 0x1f && body[1] == 0x8b) {
        let mut gz = GzDecoder::new(&body[..]);
        let mut out = Vec::new();
        if gz.read_to_end(&mut out).is_ok() && !out.is_empty() {
            body = out;
        }
    }
    Some(body)
}

fn dechunk(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let Some(crlf) = find_subslice(&raw[i..], b"\r\n") else {
            break;
        };
        let len_str = String::from_utf8_lossy(&raw[i..i + crlf]);
        let hex_part = len_str.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(hex_part, 16) else {
            break;
        };
        i += crlf + 2;
        if chunk_len == 0 {
            break;
        }
        let end = (i + chunk_len).min(raw.len());
        out.extend_from_slice(&raw[i..end]);
        i = end;
        if i + 2 <= raw.len() && &raw[i..i + 2] == b"\r\n" {
            i += 2;
        }
    }
    if out.is_empty() {
        raw.to_vec()
    } else {
        out
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn run_dns_loop(sock: UdpSocket, redirect_ip: Ipv4Addr, ctx: Arc<RuntimeCtx>) {
    let mut buf = [0u8; 4096];
    while !ctx.stop.load(Ordering::SeqCst) {
        let Ok((n, client)) = sock.recv_from(&mut buf) else {
            continue;
        };
        if ctx.stop.load(Ordering::SeqCst) || n < 14 {
            continue;
        }
        let packet = buf[..n].to_vec();
        let sock_c = match sock.try_clone() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let ctx_c = ctx.clone();
        thread::spawn(move || handle_dns_packet(&packet, client, sock_c, redirect_ip, &ctx_c));
    }
}

fn handle_dns_packet(
    data: &[u8],
    client: SocketAddr,
    sock: UdpSocket,
    redirect_ip: Ipv4Addr,
    ctx: &RuntimeCtx,
) {
    let Some((qname, qtype, qoff)) = parse_dns_question(data) else {
        return;
    };
    let name = qname.to_ascii_lowercase();
    if name == TARGET_HOST {
        emit(
            &ctx.app,
            "dns_redirect",
            format!("DNS yönlendirildi: {name} (tip {qtype})"),
            Some(client.ip().to_string()),
            None,
        );
        let resp = build_dns_response(data, redirect_ip, qtype, qoff);
        let _ = sock.send_to(&resp, client);
        return;
    }
    if let Ok(up) = UdpSocket::bind("0.0.0.0:0") {
        let _ = up.set_read_timeout(Some(Duration::from_secs(4)));
        if up.send_to(data, "8.8.8.8:53").is_ok() {
            let mut rbuf = [0u8; 4096];
            if let Ok((rn, _)) = up.recv_from(&mut rbuf) {
                let _ = sock.send_to(&rbuf[..rn], client);
            }
        }
    }
}

fn parse_dns_question(data: &[u8]) -> Option<(String, u16, usize)> {
    let mut off = 12usize;
    let mut labels = Vec::new();
    while off < data.len() {
        let ln = data[off] as usize;
        if ln == 0 {
            off += 1;
            break;
        }
        if (ln & 0xC0) != 0 || off + 1 + ln > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[off + 1..off + 1 + ln]).to_string());
        off += 1 + ln;
    }
    if off + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[off], data[off + 1]]);
    Some((labels.join("."), qtype, off + 4))
}

fn build_dns_response(query: &[u8], ip: Ipv4Addr, qtype: u16, qoff: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(qoff + 32);
    out.extend_from_slice(&query[..2]);
    out.extend_from_slice(&[0x81, 0x80]);
    out.extend_from_slice(&1u16.to_be_bytes());
    if qtype == 1 {
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&query[12..qoff]);
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&5u32.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    } else {
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&query[12..qoff]);
    }
    out
}

fn build_mobile_landing_html(lan_ip: &str, port: u16, mode: &str) -> String {
    let net_block = if mode == "dns" {
        format!(
            r#"<section class="step">
      <div class="sh"><span class="snum">3</span><h2>Wi-Fi DNS → Elle</h2></div>
      <div class="path">Ayarlar › Wi-Fi › (ⓘ) › DNS › Elle</div>
      <div class="copy-card">
        <div class="cv"><small>DNS SUNUCUSU</small><code>{lan_ip}</code></div>
        <button type="button" class="cbtn" onclick="cp('{lan_ip}',this)">Kopyala</button>
      </div>
    </section>"#
        )
    } else {
        format!(
            r#"<section class="step">
      <div class="sh"><span class="snum">3</span><h2>Wi-Fi Proxy → Elle</h2></div>
      <div class="path">Ayarlar › Wi-Fi › (ⓘ) › Proxy'yi Ayarla › Elle › Kaydet</div>
      <div class="copy-card">
        <div class="cv"><small>SUNUCU (SERVER)</small><code>{lan_ip}</code></div>
        <button type="button" class="cbtn" onclick="cp('{lan_ip}',this)">Kopyala</button>
      </div>
      <div class="copy-card">
        <div class="cv"><small>KAPI (PORT)</small><code>{port}</code></div>
        <button type="button" class="cbtn" onclick="cp('{port}',this)">Kopyala</button>
      </div>
    </section>"#
        )
    };

    format!(
        r#"<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, viewport-fit=cover">
<meta name="format-detection" content="telephone=no">
<title>Peyywado OTP — iPhone Kurulum</title>
<style>
  *,*::before,*::after{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
  html{{
    font-size:17px;
    -webkit-text-size-adjust:100%;
    text-size-adjust:100%;
    background:#07090e;
    overflow-x:hidden;
    max-width:100%;
  }}

  @media (pointer:coarse) and (min-width:700px){{
    html{{font-size:clamp(28px, 4.2vw, 42px)}}
  }}
  body{{
    margin:0;
    min-height:100dvh;
    width:100%;
    max-width:100%;
    overflow-x:hidden;
    padding:max(1.1rem, env(safe-area-inset-top)) 0.95rem max(2.2rem, env(safe-area-inset-bottom));
    background:radial-gradient(120% 40% at 85% 0%, rgba(249,115,22,.16), transparent 65%), #07090e;
    color:#f1f5fb;
    font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','SF Pro Text','Segoe UI',sans-serif;
    line-height:1.4;
  }}
  .app{{
    width:100%;
    max-width:34rem;
    margin:0 auto;
    display:flex;
    flex-direction:column;
    gap:0.9rem;
  }}
  @media (pointer:coarse){{
    .app{{max-width:100%}}
  }}
  .head{{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:0.6rem;
    padding:0.2rem 0.15rem;
  }}
  h1{{margin:0;font-size:1.55rem;font-weight:800;letter-spacing:-.025em;color:#ffffff}}
  h1 span{{color:#fb923c}}
  .badge{{
    font-size:0.78rem;font-weight:800;padding:0.35rem 0.7rem;border-radius:999px;
    background:rgba(16,185,129,.15);color:#34d399;border:1px solid rgba(16,185,129,.35);
    white-space:nowrap;
  }}
  .btn{{
    display:flex;align-items:center;justify-content:center;gap:0.5rem;
    width:100%;min-height:3.65rem;padding:0.95rem 1.1rem;border-radius:1rem;
    text-decoration:none;font-weight:800;font-size:1.12rem;letter-spacing:-.01em;
    transition:transform .12s ease;
  }}
  .btn:active{{transform:scale(.98)}}
  .btn-primary{{
    background:linear-gradient(135deg,#fb923c,#ea580c);
    color:#160900;
    box-shadow:0 0.55rem 1.6rem rgba(249,115,22,.34);
  }}
  .btn-hint{{
    margin:-0.45rem 0 0;
    text-align:center;
    font-size:0.86rem;
    color:#94a3b8;
  }}
  .btn-sec{{
    background:linear-gradient(135deg,rgba(16,185,129,.22),rgba(16,185,129,.12));
    color:#34d399;
    border:1.5px solid rgba(16,185,129,.5);
  }}
  .step{{
    background:#101521;
    border:1px solid rgba(148,172,214,.2);
    border-radius:1.15rem;
    padding:1rem;
    display:flex;
    flex-direction:column;
    gap:0.65rem;
  }}
  .sh{{display:flex;align-items:center;gap:0.65rem}}
  .snum{{
    width:1.85rem;height:1.85rem;border-radius:0.55rem;flex:none;
    background:rgba(249,115,22,.18);color:#fb923c;
    font-weight:800;font-size:0.95rem;
    display:flex;align-items:center;justify-content:center;
  }}
  .step h2{{margin:0;font-size:1.1rem;font-weight:800;color:#ffffff;letter-spacing:-.01em}}
  .path{{
    font-size:0.92rem;
    color:#cbd5e1;
    background:#090d16;
    border:1px solid rgba(148,172,214,.14);
    border-radius:0.7rem;
    padding:0.55rem 0.75rem;
    font-weight:600;
    word-break:break-word;
  }}
  .ios-row{{
    display:flex;align-items:center;justify-content:space-between;gap:0.6rem;
    background:#151d2f;border:1px solid rgba(148,172,214,.22);
    border-radius:0.8rem;padding:0.75rem 0.85rem;
    font-size:0.95rem;color:#ffffff;font-weight:700;
  }}
  .ios-row span:first-child{{min-width:0;overflow-wrap:anywhere}}
  .ios-tag{{color:#fb923c;font-weight:800;white-space:nowrap}}
  .sw{{width:2.7rem;height:1.6rem;border-radius:999px;background:#22c55e;position:relative;flex:none}}
  .sw::after{{content:"";position:absolute;top:0.15rem;right:0.15rem;width:1.3rem;height:1.3rem;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.35)}}
  .copy-card{{
    display:flex;align-items:center;justify-content:space-between;gap:0.7rem;
    background:#151d2f;border:1px solid rgba(148,172,214,.22);
    border-radius:0.85rem;padding:0.75rem 0.85rem;
  }}
  .cv{{display:flex;flex-direction:column;gap:0.12rem;min-width:0}}
  .cv small{{font-size:0.7rem;font-weight:800;letter-spacing:.05em;color:#94a3b8}}
  .cv code{{
    font-family:ui-monospace,'SF Mono',Menlo,monospace;
    font-size:1.32rem;font-weight:800;color:#fb923c;
    letter-spacing:0.01em;word-break:break-all;
  }}
  .cbtn{{
    flex:none;border:none;border-radius:0.7rem;
    min-height:2.75rem;padding:0 1.05rem;
    background:rgba(249,115,22,.22);color:#fb923c;
    font-family:inherit;font-weight:800;font-size:0.95rem;
    cursor:pointer;white-space:nowrap;
  }}
  .cbtn:active{{transform:scale(.96)}}
  .cbtn.ok{{background:rgba(16,185,129,.25);color:#34d399}}
  .note{{
    font-size:0.88rem;color:#94a3b8;text-align:center;
    padding:0.3rem 0.4rem 0;
  }}
  .note b{{color:#e2e8f0}}
</style>
</head>
<body>
  <main class="app">
    <header class="head">
      <h1>Peyywado <span>OTP</span></h1>
      <span class="badge">🔒 Yerel Wi-Fi</span>
    </header>

    <a class="btn btn-primary" href="/ca.mobileconfig">1. Sertifika Profilini İndir</a>
    <p class="btn-hint">Açılan pencerede <b>İzin Ver</b>'e dokun</p>

    <section class="step">
      <div class="sh"><span class="snum">2</span><h2>Yükle & Tam Güven Aç</h2></div>
      <div class="ios-row"><span>Ayarlar › Profil İndirildi</span><span class="ios-tag">Yükle ›</span></div>
      <div class="path">Genel › Hakkında › Sertifika Güven Ayarları</div>
      <div class="ios-row"><span>Peyywado OTP Gecici CA</span><span class="sw" aria-hidden="true"></span></div>
    </section>

    {net_block}

    <a class="btn btn-sec" href="https://otpservice.nttgame.com/__peyywado_test">✓ 4. Bağlantıyı Test Et</a>

    <p class="note">🔒 %100 Yerel · İşlem bitince <b>Proxy → Kapalı</b> yap</p>
  </main>
<script>
function cp(txt,btn){{
  var done=function(){{var o=btn.textContent;btn.textContent='Kopyalandı ✓';btn.classList.add('ok');setTimeout(function(){{btn.textContent=o;btn.classList.remove('ok')}},1500)}};
  if(navigator.clipboard&&navigator.clipboard.writeText){{navigator.clipboard.writeText(txt).then(done).catch(function(){{fb(txt,done)}})}}else{{fb(txt,done)}}
}}
function fb(t,cb){{var a=document.createElement('textarea');a.value=t;a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();try{{document.execCommand('copy');cb()}}catch(e){{}}document.body.removeChild(a)}}
</script>
</body>
</html>"#
    )
}

fn build_mobile_test_ok_html() -> String {
    r#"<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, viewport-fit=cover">
<title>Bağlantı Hazır — Peyywado OTP</title>
<style>
  *{box-sizing:border-box}
  html{font-size:17px;-webkit-text-size-adjust:100%;background:#07090e;overflow-x:hidden}
  @media (pointer:coarse) and (min-width:700px){html{font-size:clamp(28px,4.2vw,42px)}}
  body{margin:0;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:1.2rem;background:#07090e;color:#f1f5fb;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',sans-serif}
  .box{max-width:30rem;width:100%;text-align:center;background:#101521;border:1.5px solid rgba(16,185,129,.45);border-radius:1.4rem;padding:2rem 1.35rem;box-shadow:0 1.4rem 3.5rem rgba(0,0,0,.55)}
  @media (pointer:coarse){.box{max-width:100%}}
  .ok{width:4.2rem;height:4.2rem;border-radius:50%;margin:0 auto 1rem;background:rgba(16,185,129,.18);color:#34d399;font-size:2.1rem;font-weight:900;display:flex;align-items:center;justify-content:center;border:2.5px solid #10b981}
  h1{margin:0 0 0.5rem;font-size:1.55rem;color:#34d399}
  p{margin:0 0 1.1rem;font-size:1rem;color:#cbd5e1}
  .next{padding:1rem;border-radius:0.95rem;background:#090d16;border:1.5px solid rgba(249,115,22,.45);color:#fb923c;font-weight:800;font-size:1.08rem}
</style>
</head>
<body>
  <div class="box">
    <div class="ok">✓</div>
    <h1>Bağlantı Hazır!</h1>
    <p>PC ekranı otomatik sonraki adıma geçti.</p>
    <div class="next">Şimdi <b>AnyOTP+</b>'ı aç ve aktive et!</div>
  </div>
</body>
</html>"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};

    #[test]
    fn ephemeral_bundle_and_tls_config_valid() {
        let b = generate_ephemeral_bundle("192.168.1.42").expect("bundle");
        assert!(!b.ca_der.is_empty());
        assert!(!b.leaf_der.is_empty());
        assert!(b.mobileconfig_xml.contains("com.apple.security.root"));
        assert!(b.mobileconfig_xml.contains("Peyywado OTP Gecici CA"));
        let _tls = build_server_tls(&b).expect("rustls server config");
    }

    #[test]
    fn dechunk_reconstructs_json_body() {
        let chunked = b"11\r\n{\"result\":\"PB0000\r\n12\r\n\",\"data\":\"sample\"}\r\n0\r\n\r\n";
        let out = dechunk(chunked);
        assert_eq!(out, br#"{"result":"PB0000","data":"sample"}"#);
    }

    #[test]
    fn extract_body_handles_gzip_response() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(br#"{"result":"PB0000","data":"ok"}"#).unwrap();
        let compressed = gz.finish().unwrap();
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        resp.extend_from_slice(&compressed);
        let body = extract_http_body(&resp).expect("body");
        assert_eq!(body, br#"{"result":"PB0000","data":"ok"}"#);
    }

    #[test]
    fn parse_absolute_uri_variants() {
        assert_eq!(
            parse_absolute_http_uri("http://time1.dreammirae.com/timesvc/index.jsp"),
            Some(("time1.dreammirae.com".into(), 80, "/timesvc/index.jsp".into()))
        );
        assert_eq!(
            parse_absolute_http_uri("http://192.168.1.6:8888/ca.mobileconfig"),
            Some(("192.168.1.6".into(), 8888, "/ca.mobileconfig".into()))
        );
        assert_eq!(parse_absolute_http_uri("/ca.mobileconfig"), None);
    }

    #[test]
    fn self_loop_filter_blocks_own_lan_and_loopback() {
        let list = vec![
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([192, 168, 1, 6], 443)),
            SocketAddr::from(([104, 20, 30, 209], 443)),
        ];
        let filtered = filter_non_loop_addrs(list, "192.168.1.6");
        assert_eq!(filtered, vec![SocketAddr::from(([104, 20, 30, 209], 443))]);
    }

    #[test]
    fn dns_parser_and_redirect_response() {
        let mut q = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in ["otpservice", "nttgame", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());

        let (name, qtype, qoff) = parse_dns_question(&q).expect("parse");
        assert_eq!(name, "otpservice.nttgame.com");
        assert_eq!(qtype, 1);

        let resp = build_dns_response(&q, Ipv4Addr::new(192, 168, 1, 6), qtype, qoff);
        assert_eq!(&resp[0..2], &[0x12, 0x34]);
        assert_eq!(&resp[resp.len() - 4..], &[192, 168, 1, 6]);

        let resp65 = build_dns_response(&q, Ipv4Addr::new(192, 168, 1, 6), 65, qoff);
        assert_eq!(&resp65[6..8], &[0x00, 0x00]);
    }

    #[test]
    fn ipv4_addresses_sorted_before_ipv6() {
        let v6: SocketAddr = "[2606:4700::1]:443".parse().unwrap();
        let v4: SocketAddr = "104.20.30.209:443".parse().unwrap();
        let sorted = sort_ipv4_first(vec![v6, v4]);
        assert!(sorted[0].is_ipv4());
    }

    #[test]
    fn detects_virtual_adapters_accurately() {
        assert!(is_virtual_adapter_name("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter"));
        assert!(is_virtual_adapter_name("VMware Network Adapter VMnet8", ""));
        assert!(is_virtual_adapter_name("CloudflareWARP", "WireGuard Tunnel"));
        assert!(is_virtual_adapter_name("ProtonVPN", "Wintun Userspace Tunnel"));
        assert!(!is_virtual_adapter_name("Wi-Fi", "Intel(R) Wi-Fi 6E AX211"));
        assert!(!is_virtual_adapter_name("Tuna Wi-Fi", "Intel(R) Wi-Fi 6E AX211"));
        assert!(!is_virtual_adapter_name("Ethernet", "Realtek PCIe 2.5GbE Family Controller"));
    }

    #[test]
    fn lan_ip_bonus_respects_rfc1918() {
        assert_eq!(lan_ip_bonus("192.168.1.6"), 0);
        assert_eq!(lan_ip_bonus("10.0.0.5"), 1);
        assert_eq!(lan_ip_bonus("172.16.0.10"), 2);
        assert_eq!(lan_ip_bonus("172.31.255.1"), 2);
        assert_eq!(lan_ip_bonus("172.217.1.1"), 3);
        assert_eq!(lan_ip_bonus("8.8.8.8"), 3);
    }
}
