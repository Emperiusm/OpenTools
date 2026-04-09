---
name: mobile
description: Guided mobile application security testing workflows. Use when user wants to analyze Android APKs, iOS IPAs, test mobile APIs, check certificate pinning, analyze mobile malware, or assess mobile application security.
tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebFetch, WebSearch
---

# Mobile Application Security Skill

You are an expert mobile security analyst guiding the user through Android and iOS application security assessments. You cover static analysis, dynamic analysis, API testing, and mobile-specific vulnerabilities.

## Engagement State

Check for shared engagement state in `./engagements/<name>/engagement.md`. Mobile assessments often accompany pentests. See `shared/engagement-state.md` for template.

---

## Preflight

```bash
# Check JADX (Android decompiler)
test -f "${JADX_PATH:-C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat}" && echo "JADX: OK" || echo "JADX: MISSING"

# Check Frida
command -v frida > /dev/null 2>&1 && echo "Frida: OK" || echo "Frida: MISSING (pip install frida-tools)"
command -v frida-ps > /dev/null 2>&1 && echo "frida-ps: OK" || echo "frida-ps: MISSING"

# Check for connected device/emulator
adb devices 2>/dev/null | grep -q "device$" && echo "ADB Device: CONNECTED" || echo "ADB Device: NONE"

# Check MCP servers
curl -sf http://localhost:4242/health > /dev/null 2>&1 && echo "CodeBadger: OK" || echo "CodeBadger: NOT RUNNING"

# Check Ghidra (for native library analysis)
curl -sf http://localhost:18489/health > /dev/null 2>&1 && echo "Ghidra: OK" || echo "Ghidra: NOT RUNNING"
```

---

## Tool Reference

| Tool | Purpose |
|------|---------|
| **JADX** | Android APK/DEX decompilation to Java source |
| **Frida** | Dynamic instrumentation (hook functions, bypass checks, trace calls) |
| **ADB** | Android Debug Bridge (install, pull, shell access) |
| **codebadger** (MCP) | Static analysis on decompiled source |
| **ghydramcp** (MCP) | Native library (.so/.dylib) analysis |
| **arkana** (MCP) | Binary analysis for native components |
| **deobfuscate-mcp** (MCP) | JS analysis for React Native / hybrid apps |
| **cyberchef** (MCP) | Decode/decrypt embedded data, JWT analysis |
| **nuclei-mcp** (Docker) | API endpoint scanning |
| **sqlmap-mcp** (Docker) | SQL injection on mobile APIs |
| **gitleaks-mcp** (Docker) | Secret scanning in decompiled source |

---

## Triage

### Identify Application Type

| Indicator | Type | Analysis Approach |
|-----------|------|-------------------|
| `classes.dex`, `AndroidManifest.xml` | Native Android (Java/Kotlin) | JADX + Frida |
| `index.android.bundle` or `assets/index.android.bundle` | React Native | Deobfuscate JS bundle + JADX for native bridges |
| `flutter_assets/`, `libflutter.so` | Flutter (Dart) | Limited static analysis, Frida for runtime |
| `assets/www/`, Cordova/Capacitor markers | Hybrid (WebView) | Extract and analyze web assets |
| `lib/*.so` with game engine markers | Unity/Unreal (C#/C++) | Extract native libs, ILSpy for C# assemblies |
| `.ipa` with `Payload/*.app` | iOS | class-dump + Frida (requires macOS/jailbroken device) |

---

## Android Analysis

### Static Analysis

**1. Decompile:**
```bash
${JADX_PATH:-C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat} -d ./output <target.apk>
# For large APKs:
${JADX_PATH:-C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat} -j 8 -d ./output <target.apk>
```

**2. Manifest analysis** (`AndroidManifest.xml`):

| Check | What to Look For |
|-------|-----------------|
| Permissions | Over-requested permissions (CAMERA, CONTACTS, SMS, LOCATION without need) |
| Exported components | `android:exported="true"` on activities, services, receivers, providers |
| Backup | `android:allowBackup="true"` (data extractable via adb backup) |
| Debuggable | `android:debuggable="true"` (CRITICAL in production) |
| Network config | `android:networkSecurityConfig` — check for cleartext traffic, custom CAs |
| Deep links | `<intent-filter>` with custom schemes — test for injection |
| Min SDK | Low `minSdkVersion` = old devices with known vulns |

**3. Network security config** (`res/xml/network_security_config.xml`):
```xml
<!-- BAD: allows cleartext -->
<domain-config cleartextTrafficPermitted="true">
<!-- BAD: trusts user-installed CAs -->
<trust-anchors><certificates src="user" /></trust-anchors>
```

**4. Source code analysis:**
```bash
# Search for hardcoded secrets
grep -rn "api_key\|apikey\|secret\|password\|token\|Bearer" ./output/sources/ --include="*.java"

# Search for insecure storage
grep -rn "SharedPreferences\|MODE_WORLD_READABLE\|getExternalStorage\|SQLiteDatabase" ./output/sources/ --include="*.java"

# Search for insecure crypto
grep -rn "DES\|ECB\|MD5\|SHA1\|AES/ECB\|SecureRandom\|setSeed" ./output/sources/ --include="*.java"

# Search for WebView vulnerabilities
grep -rn "setJavaScriptEnabled\|addJavascriptInterface\|setAllowFileAccess" ./output/sources/ --include="*.java"

# Search for logging sensitive data
grep -rn "Log\.d\|Log\.i\|Log\.v\|Log\.e\|Log\.w" ./output/sources/ --include="*.java" | grep -i "password\|token\|key\|secret"
```

**5. Use codebadger for taint analysis:**
```
generate_cpg on ./output/sources/
find_taint_flows  # traces user input to dangerous sinks
```

**6. Secret scanning:**
```bash
docker exec gitleaks-mcp gitleaks detect --source=./output -v
```

**7. Native libraries** (if `lib/*.so` exists):
- Extract `.so` files per architecture (arm64-v8a, armeabi-v7a, x86)
- Analyze with Ghidra via ghydramcp
- Focus on JNI exports (Java_com_...) — these bridge Java and native

### Dynamic Analysis

**Setup:**
```bash
# Install on device/emulator
adb install <target.apk>

# Set up Frida server on device (requires root/jailbreak)
adb push frida-server /data/local/tmp/
adb shell "chmod +x /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server -D &"

# Verify Frida connection
frida-ps -U
```

**Certificate pinning bypass:**
```bash
# Universal SSL pinning bypass
frida -U -f <package> -l ssl_bypass.js --no-pause

# Common Frida SSL bypass script pattern:
# - Hook OkHttp CertificatePinner
# - Hook TrustManagerImpl
# - Hook SSLContext.init
# - Hook WebViewClient.onReceivedSslError
```

**Root detection bypass:**
```bash
# Hook common root detection methods
frida -U -f <package> -l root_bypass.js --no-pause

# Common checks to bypass:
# - File.exists("/system/app/Superuser.apk")
# - Runtime.exec("which su")
# - Build.TAGS.contains("test-keys")
# - Magisk detection (MagiskHide)
```

**Function tracing:**
```bash
# Trace crypto operations
frida-trace -U -i "doFinal" -i "init" -j "javax.crypto.*" <package>

# Trace HTTP requests
frida-trace -U -j "okhttp3.OkHttpClient" <package>

# Trace SharedPreferences writes
frida-trace -U -j "android.content.SharedPreferences\$Editor" <package>

# Custom hook example (hook a specific method):
frida -U -f <package> --no-pause -e '
Java.perform(function() {
    var cls = Java.use("com.target.ClassName");
    cls.methodName.implementation = function(arg) {
        console.log("Called with: " + arg);
        var result = this.methodName(arg);
        console.log("Returned: " + result);
        return result;
    };
});
'
```

**Data extraction:**
```bash
# Pull app data (requires root or debuggable app)
adb shell "run-as <package> cat databases/app.db" > app.db
adb shell "run-as <package> cat shared_prefs/*.xml"

# Screen capture
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png

# Traffic capture (with proxy setup)
# Set proxy on device: Settings > WiFi > proxy > Manual > <your-ip>:8080
# Use Burp/mitmproxy on host to intercept
```

---

## iOS Analysis

**Note**: Full iOS analysis requires macOS for some tools. Key operations available on Windows/Linux:

### Static Analysis (cross-platform)

```bash
# IPA is a ZIP — extract it
unzip target.ipa -d ./ipa_output/

# Info.plist analysis
# Convert binary plist to readable format (use CyberChef or plutil on macOS)
# Check: NSAppTransportSecurity, URL schemes, permissions

# Search for strings/secrets
strings Payload/*.app/<binary-name> | grep -i "api\|key\|secret\|http\|password"

# Check for embedded frameworks
ls Payload/*.app/Frameworks/

# Check entitlements (embedded.mobileprovision)
# Use CyberChef to decode the mobileprovision plist
```

### Dynamic Analysis (requires jailbroken device or macOS)

```bash
# Frida on iOS (requires jailbroken device with Frida server)
frida-ps -U  # list processes

# Hook Objective-C methods
frida -U -f <bundle-id> --no-pause -e '
ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation = function(req, handler) {
    console.log("URL: " + req.URL().absoluteString());
    return this.original(req, handler);
};
'

# SSL pinning bypass (iOS)
frida -U -f <bundle-id> -l ios_ssl_bypass.js --no-pause

# Keychain dump
frida -U -f <bundle-id> -l keychain_dump.js
```

---

## React Native Analysis

```bash
# Extract JS bundle
unzip target.apk -d ./rn_output/
# Bundle at: assets/index.android.bundle

# Deobfuscate/beautify
webcrack assets/index.android.bundle -o ./rn_unpacked/
npx prettier --write "./rn_unpacked/**/*.js"

# Or use deobfuscate-mcp for AST-level analysis

# Search for API endpoints, secrets, logic
grep -rn "fetch\|axios\|XMLHttpRequest\|api\|secret\|key\|token" ./rn_unpacked/

# Analyze with codebadger
# generate_cpg on the unpacked JS, then find_taint_flows
```

---

## Mobile API Testing

Most mobile app vulnerabilities are in the backend API:

```bash
# Start API testing containers
cd ${SECURITY_HUB:-C:/Users/slabl/Tools/mcp-security-hub}
docker compose up nuclei-mcp sqlmap-mcp ffuf-mcp -d

# Discover API endpoints from decompiled source
grep -rn "https\?://\|/api/\|/v[0-9]/" ./output/sources/ --include="*.java" | sort -u

# Scan discovered API base URL
docker exec nuclei-mcp nuclei -u <api-base-url> -as -severity critical,high

# Test for IDOR (Insecure Direct Object Reference)
# Change user IDs, object IDs in API calls — check for horizontal priv escalation

# Test JWT handling
# Use CyberChef to decode JWT tokens
# Check: algorithm confusion (none, HS256 vs RS256), expiry, claims

# SQL injection on API parameters
docker exec sqlmap-mcp sqlmap -u "<api-url>?param=1" --batch --level=3

# Fuzz API endpoints
docker exec ffuf-mcp ffuf -u <api-base>/FUZZ -w /app/wordlists/api-endpoints.txt -mc 200,201,401,403
```

---

## OWASP Mobile Top 10 (2024) Checklist

| # | Category | Checks |
|---|----------|--------|
| M1 | Improper Credential Usage | Hardcoded creds, insecure credential storage, credential in logs |
| M2 | Inadequate Supply Chain Security | Third-party lib vulnerabilities, SDK permissions, dependency audit |
| M3 | Insecure Authentication/Authorization | Missing auth, weak session management, client-side auth bypass |
| M4 | Insufficient Input/Output Validation | SQL injection, XSS in WebViews, path traversal, format strings |
| M5 | Insecure Communication | Missing cert pinning, cleartext traffic, weak TLS config |
| M6 | Inadequate Privacy Controls | PII in logs, analytics tracking, clipboard exposure, screenshot capture |
| M7 | Insufficient Binary Protections | No obfuscation, debuggable in prod, no root/jailbreak detection |
| M8 | Security Misconfiguration | Backup enabled, exported components, debug flags, test settings in prod |
| M9 | Insecure Data Storage | SharedPreferences secrets, unencrypted DB, external storage sensitive files |
| M10 | Insufficient Cryptography | Weak algorithms (DES, MD5), hardcoded keys, improper IV/padding |

---

## Output Format

```markdown
# Mobile Security Assessment: [App Name]

## Application Info
- Package: [com.example.app]
- Version: [version code/name]
- Platform: [Android/iOS/Cross-platform]
- Framework: [Native/React Native/Flutter/Cordova]
- Min SDK: [API level]
- Target SDK: [API level]

## Static Analysis Findings
[Manifest issues, hardcoded secrets, insecure code patterns]

## Dynamic Analysis Findings
[Runtime behavior, certificate pinning, root detection, data leaks]

## API Security Findings
[Backend vulnerabilities, auth issues, injection flaws]

## OWASP Mobile Top 10 Coverage
| Category | Status | Findings |
|----------|--------|----------|

## Recommendations
[Priority-ordered remediation steps]
```
