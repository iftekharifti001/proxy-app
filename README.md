# ProxyConnect — Android SOCKS5 / HTTP Proxy App

System-wide proxy connector using `VpnService` (no root required).
Enter host, port, type (SOCKS5 / HTTP), optional username + password, tap Connect.

## Features
- SOCKS5 with / without auth (RFC 1928 / RFC 1929)
- HTTP proxy with / without auth (`CONNECT` + `Proxy-Authorization: Basic`)
- Remote DNS (hostname sent to proxy, no local leak for TCP)
- DNS-over-TCP via proxy for UDP port 53 lookups
- Reconnect, persistent config, foreground notification, logs

## Project layout
```
proxy-app/                <- native Android project (open this in Android Studio)
  settings.gradle
  build.gradle
  gradle.properties
  app/build.gradle
  app/src/main/AndroidManifest.xml
  app/src/main/java/com/proxyconnect/app/...
  app/src/main/res/...
.github/workflows/build-apk.yml   <- builds debug APK in the cloud
```

## Option A — Get APK without installing anything (recommended)

1. Create a GitHub repo and push this folder:
   ```bash
   git init
   git add .
   git commit -m "proxy app"
   git branch -M main
   git remote add origin https://github.com/YOU/proxyconnect.git
   git push -u origin main
   ```
2. Go to repo → **Actions** → **Build debug APK** → Run (it also runs on every push).
3. After it finishes, download artifact **ProxyConnect-debug-apk**.
4. Inside is `app-debug.apk`. Copy to your phone, allow "Install unknown apps", install.

## Option B — Build locally in Android Studio

1. Install [Android Studio](https://developer.android.com/studio).
2. Open `proxy-app/` (not the repo root).
3. Let it sync Gradle (AGP 8.5.2, Kotlin 1.9.24, compileSdk 34, minSdk 26).
4. Run on phone (USB debugging) or **Build → Build APK(s)**.
5. APK output: `proxy-app/app/build/outputs/apk/debug/app-debug.apk`.

## Usage on phone
1. Open ProxyConnect.
2. Type: SOCKS5 or HTTP.
3. Host (e.g. `123.45.67.89` or `proxy.example.com`), Port (e.g. `1080` / `8080`).
4. Toggle Authentication if needed, enter Username / Password.
5. Tap **Connect** → accept VPN permission → notification shows "ProxyConnect active".
6. Test IP in browser. Tap **Disconnect** to stop.

## Notes / limits
- TCP is tunnelled through the proxy. UDP (games/calls) except DNS is dropped — this is standard for SOCKS5/HTTP proxy apps. DNS queries are forwarded over TCP through the proxy so sites still resolve.
- If auth fails you get `SOCKS5 auth failed` / `HTTP proxy: 407` in the log — double-check user/pass.
- No root needed. Works on Android 8.0+.
- This is a personal proxy connector, not a VPN provider. You must supply your own SOCKS5/HTTP server.
