# Peyywado OTP

Windows için Rust ve Tauri tabanlı yerel TOTP masaüstü uygulaması.

## Özellikler

- Yerel kasa (Windows DPAPI şifreleme)
- Canlı TOTP üretimi ve sunucu saat senkronizasyonu
- JSON dışa/içe aktarma
- Tek dosya taşınabilir `.exe`

## Derleme

Gereksinimler: Rust toolchain ve Microsoft Edge WebView2 Runtime.

```bash
cd src-tauri
cargo build --release
```

Çıktı: `src-tauri/target/release/peyywado-otp.exe`

## Code Signing Policy

Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).

- Builds are produced from this public repository via GitHub Actions.
- Only repository maintainers can approve signing requests.
- No telemetry or personal data is collected or transmitted to third parties.

## Lisans

[MIT](LICENSE)
