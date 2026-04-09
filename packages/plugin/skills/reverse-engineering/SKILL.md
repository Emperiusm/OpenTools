---
name: reverse-engineering
description: Guided reverse engineering and deobfuscation workflows. Use when user wants to analyze binaries, decompile executables, deobfuscate code, analyze malware, reverse engineer protocols, or understand compiled/packed/obfuscated software.
tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebFetch
---

# Reverse Engineering Skill

You are an expert reverse engineer with 50+ tools for binary analysis, decompilation, deobfuscation, malware analysis, and protocol RE. Tool paths and configs are in `config/tools.yaml`.

## Engagement State

**Always** check for a shared engagement state file in `./engagements/<name>/engagement.md`. If this RE session is part of a pentest, read it first for context. Log all findings back to it. See `shared/engagement-state.md` for the template.

---

## Preflight Check

```bash
# Verify Ghidra is running (required for most RE workflows)
curl -sf http://localhost:18489/health && echo "Ghidra: OK" || echo "Ghidra: NOT RUNNING - start Ghidra with GhydraMCP plugin"

# Check Arkana Docker image
docker image inspect arkana:latest > /dev/null 2>&1 && echo "Arkana: OK" || echo "Arkana: NOT PULLED - run: docker pull arkana:latest"

# Check analysis containers
for container in yara-mcp capa-mcp binwalk-mcp radare2-mcp; do
  status=$(docker ps --filter name=$container --filter status=running -q)
  if [ -n "$status" ]; then echo "$container: RUNNING"; else echo "$container: STOPPED"; fi
done

# Check CLI decompilers
test -f "${JADX_PATH:-C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat}" && echo "JADX: OK" || echo "JADX: MISSING"
test -f "${RETDEC_PATH:-C:/Users/slabl/Tools/retdec/retdec-v5.0/bin/retdec-decompiler.exe}" && echo "RetDec: OK" || echo "RetDec: MISSING"
command -v webcrack > /dev/null 2>&1 && echo "webcrack: OK" || echo "webcrack: MISSING"
```

**If Ghidra is not running**: Use RetDec + Arkana as fallback. If Arkana is not available, use radare2-mcp + RetDec.

---

## Tool Reference

### MCP Servers

| Server | Key Tools |
|--------|-----------|
| **ghydramcp** | `functions_list`, `functions_decompile`, `functions_disassemble`, `xrefs_list`, `symbols_imports`, `symbols_exports`, `memory_read`, `data_list_strings`, `structs_*`, `analysis_run` |
| **arkana** | 250+ tools: PE/ELF/Mach-O parsing, angr symbolic execution, YARA/capa, Qiling/Speakeasy emulation, .NET deobfuscation, binary-refinery, string analysis, VirusTotal, Rust/Go analysis |
| **codebadger** | CPG analysis on decompiled source: `generate_cpg`, `get_call_graph`, `get_cfg`, `find_taint_flows`, `get_variable_flow` |
| **cyberchef** | XOR bruteforce, Base64, AES/RC4 decrypt, hex decode, protobuf decode, decompress, and 460+ more |
| **deobfuscate-mcp** | JS-specific: AST parsing, bundle splitting, source map recovery, identifier renaming |

### Decompilers (CLI via Bash)

```bash
# Java / Android APK / DEX
${JADX_PATH:-C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat} -d ./output <target.apk>
${JADX_PATH:-C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat} -j 8 -d ./output <target.apk>  # parallel

# .NET assemblies (GUI — opens ILSpy window)
${ILSPY_PATH:-C:/Users/slabl/Tools/ilspy/ILSpy/ILSpy.exe} <assembly.dll>

# Native binary -> C (ARM, MIPS, x86, PPC, etc.)
${RETDEC_PATH:-C:/Users/slabl/Tools/retdec/retdec-v5.0/bin/retdec-decompiler.exe} <binary>
# Produces: <binary>.c (decompiled C) and <binary>.dsm (disassembly)
```

### Deobfuscators (CLI via Bash)

```bash
# JavaScript — obfuscator.io, webpack bundles
webcrack <file.js>              # deobfuscate + unpack webpack
webcrack <file.js> -o ./out/    # output to directory

# JavaScript — javascript-obfuscator output
synchrony <file.js>

# JavaScript — beautify (after deobfuscation)
npx prettier --write <file.js>
```

### Docker Analysis Containers

```bash
cd ${SECURITY_HUB:-C:/Users/slabl/Tools/mcp-security-hub}
docker compose --profile re up -d  # start all RE containers

# YARA signature matching
docker exec yara-mcp yara /app/rules/*.yar <sample>

# capa capability analysis (maps to MITRE ATT&CK)
docker exec capa-mcp capa <binary>

# binwalk firmware extraction
docker exec binwalk-mcp binwalk <firmware>         # scan signatures
docker exec binwalk-mcp binwalk -E <firmware>       # entropy analysis
docker exec binwalk-mcp binwalk -eM <firmware>      # recursive extract

# radare2 scripted analysis
docker exec radare2-mcp r2 -q -c "aaa; afl" <binary>         # analyze + list functions
docker exec radare2-mcp r2 -q -c "aaa; pdf @main" <binary>   # decompile main
```

### Other CLI Tools

```bash
# Memory forensics — delegate to forensics skill for full workflow
vol -f <memory.dump> windows.info
vol -f <memory.dump> windows.pslist
vol -f <memory.dump> windows.malfind

# Dynamic instrumentation (mobile/native)
frida -U -f <package> -l <script.js>
frida-ps -U
frida-trace -U -i "open*" <package>
```

---

## Triage Workflow

When presented with an unknown file:

### Step 1: Identify

```bash
file <target>
xxd <target> | head -20
strings <target> | head -50
```

**Magic Bytes Reference:**

| Bytes (hex) | Format |
|-------------|--------|
| `4D 5A` | PE (.exe, .dll) — check for .NET CLI header at offset 0x80+ |
| `7F 45 4C 46` | ELF (Linux/embedded) |
| `FE ED FA CE/CF` | Mach-O (macOS/iOS, 32/64-bit) |
| `CA FE BA BE` | Mach-O fat binary OR Java class file |
| `50 4B 03 04` | ZIP (also APK, JAR, DOCX, XLSX) |
| `64 65 78 0A` | DEX (Android Dalvik) |
| `42 5A 68` | BZip2 compressed |
| `1F 8B` | Gzip compressed |
| `FD 37 7A 58 5A` | XZ compressed |
| `89 50 4E 47` | PNG image |
| `25 50 44 46` | PDF |
| `D0 CF 11 E0` | OLE2 (DOC, XLS, PPT — check for macros) |
| High entropy throughout | Encrypted or packed — check for packer signatures |

### Step 2: Route

| File Type | Analysis Pipeline |
|-----------|------------------|
| PE (.exe/.dll) native | -> **Native Binary Analysis** |
| PE with .NET CLI header | -> **.NET Analysis** |
| ELF / Mach-O | -> **Native Binary Analysis** |
| APK / DEX / JAR | -> **Java/Android Analysis** (or delegate to `/mobile`) |
| .js / webpack bundle | -> **JavaScript Analysis** |
| .pyc / PyInstaller exe | -> **Python Analysis** |
| Go binary (large, static) | -> **Go Binary Analysis** |
| Rust binary | -> **Rust Binary Analysis** |
| Packed/encrypted | -> **Unpacking** first, then re-triage |
| Network capture (.pcap) | -> **Protocol RE** |
| Memory dump (.dmp/.raw) | -> **Memory Forensics** (delegate to `/forensics`) |
| Firmware image | -> **Hardware RE** (delegate to `/hardware-re`) |

---

## Analysis Pipelines

### Native Binary Analysis (PE/ELF/Mach-O)

**1. Automated triage with Arkana** (via MCP):
- Format detection, architecture, compiler identification
- YARA signature matching (malware families, packers)
- capa capability analysis (ATT&CK mapping)
- String extraction and ranking (stringsifter)
- Import/export analysis

**2. Ghidra deep analysis** (via ghydramcp):

First, ensure Ghidra is running with the binary loaded:
```
ghydramcp: instances_list()  → find available instances
ghydramcp: instances_use(<port>)  → select instance
```

Then:
```
functions_list()            → survey all functions
functions_decompile(<addr>) → decompile specific function
symbols_imports()           → API surface (what does it call?)
symbols_exports()           → what does it expose?
xrefs_list(<addr>)          → who calls this / what does it reference?
data_list_strings()         → string table
analysis_run()              → trigger full auto-analysis
```

**3. RetDec alternative decompilation:**
```bash
${RETDEC_PATH:-C:/Users/slabl/Tools/retdec/retdec-v5.0/bin/retdec-decompiler.exe} <binary>
# Compare RetDec output with Ghidra for confidence
```

**4. radare2 for scripted analysis:**
```bash
docker exec radare2-mcp r2 -q -c "aaa; afl; pdf @main; iz" <binary>
```

**5. Static vuln scan on decompiled code:**
Use codebadger `generate_cpg` on RetDec's `.c` output, then `find_taint_flows`.

**Malware-specific additions:**
- Check for anti-analysis: `capa <binary>` shows debugger/VM detection capabilities
- Use Arkana's Speakeasy/Qiling emulation for dynamic behavior
- Extract IoCs: C2 domains, mutex names, registry keys, file paths
- Use CyberChef to decrypt embedded strings (XOR, AES, RC4, custom)
- Look up hashes on VirusTotal via Arkana

### Go Binary Analysis

Go binaries are increasingly common in malware (Cobalt Strike loaders, ransomware, tunneling tools). They have unique characteristics:

**Identification:**
- Very large static binaries (10-50MB+ for simple programs)
- Contains `runtime.` and `main.` symbol prefixes
- String table contains Go module paths (e.g., `github.com/...`)
- `go buildid` string present in binary headers

**Analysis pipeline:**
1. **Arkana**: Use `go_analyze` for automated Go binary analysis
   - Recovers function names even in stripped binaries
   - Identifies Go version and module dependencies
   - Extracts type information from Go runtime structures
2. **Ghidra**: Load with Go analysis scripts
   - Search for `runtime.gopanic`, `runtime.goexit` as entry point landmarks
   - Go's calling convention uses stack-based args (not registers) on older versions
   - String literals are stored as `{pointer, length}` pairs, not null-terminated
3. **String recovery**: Go strings are NOT null-terminated
   ```
   # In Ghidra, look for patterns:
   #   LEA RAX, [string_addr]
   #   MOV RBX, <length>
   # Use Arkana's extract_strings_from_binary with Go-aware mode
   ```
4. **Interface reconstruction**: Use Arkana to recover Go interface tables (`itab`)
5. **Goroutine analysis**: Identify concurrent behavior patterns

### Rust Binary Analysis

Rust binaries are growing in both legitimate and malicious use (BlackCat/ALPHV ransomware, etc.).

**Identification:**
- Contains mangled symbols like `_ZN`, `_R` (v0 mangling), or `h` suffixed hashes
- Strings contain `rust` paths, `core::`, `std::`, `alloc::`
- Panic messages with file paths ending in `.rs`

**Analysis pipeline:**
1. **Arkana**: Use `rust_analyze` and `rust_demangle_symbols` for Rust-specific analysis
   - Demangles Rust symbol names to readable form
   - Identifies Rust version and crate dependencies
   - Maps trait implementations
2. **Symbol demangling** (critical first step):
   ```
   # Arkana: rust_demangle_symbols() — converts mangled names to readable Rust paths
   # This makes the function list navigable
   ```
3. **Ghidra analysis**:
   - Apply Rust demangling before analysis
   - Rust uses same calling convention as C (SysV ABI / Microsoft x64)
   - Match/enum patterns compile to jump tables — identify these in CFG
   - `Result<T,E>` and `Option<T>` create branching patterns at every error check
4. **Panic handler tracing**: Search for `panic` strings to find error paths — these often reveal logic structure
5. **Crate identification**: String search for crate names reveals dependencies (crypto libraries, networking stacks)

### .NET Analysis

1. **Check for obfuscation** (via Arkana):
   - ConfuserEx, SmartAssembly, Dotfuscator, .NET Reactor signatures
   - Arkana has de4dot-cex and NETReactorSlayer built in

2. **Decompile with ILSpy:**
   ```bash
   ${ILSPY_PATH:-C:/Users/slabl/Tools/ilspy/ILSpy/ILSpy.exe} <assembly.dll>
   ```

3. **If obfuscated, deobfuscate first** (via Arkana MCP tools):
   - `dotnet_deobfuscate(method='de4dot')` — general purpose
   - `dotnet_deobfuscate(method='reactor_slayer')` — .NET Reactor specific

4. **Scan decompiled source** with codebadger for vulnerabilities

### Java / Android Analysis

1. **Decompile:**
   ```bash
   ${JADX_PATH:-C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat} -d ./output <target.apk>
   ```

2. **For APKs, review:**
   - `AndroidManifest.xml` — permissions, activities, services, receivers, exported components
   - `res/xml/` — network security config, backup rules
   - `assets/` — embedded databases, config files, certificates

3. **Check for native libraries** in `lib/` — extract `.so` files and analyze with Ghidra

4. **Scan decompiled Java** with codebadger for taint analysis (SQL injection, path traversal, etc.)

5. **Dynamic analysis** with Frida:
   ```bash
   frida -U -f com.target.app --no-pause -l hook_crypto.js
   ```

### JavaScript Analysis

**Detect obfuscation type:**

| Pattern | Type | Tool |
|---------|------|------|
| `_0x` hex variable names, string array rotation | obfuscator.io | `webcrack` |
| `b`, `o`, `i`, `0` variable names, self-defending | javascript-obfuscator | `synchrony` |
| `webpackJsonp`, `__webpack_require__` | Webpack bundle | `webcrack -o ./out/` |
| Minified but readable after formatting | Just minified | `npx prettier --write` |
| Unknown/custom | AST analysis needed | deobfuscate-mcp |

**Multi-stage pipeline:**
```bash
# Stage 1: Unpack/deobfuscate
webcrack packed.js -o ./unpacked/

# Stage 2: Beautify
npx prettier --write "./unpacked/**/*.js"

# Stage 3: Analyze data flows
# Use codebadger: generate_cpg on unpacked JS, then find_taint_flows

# Stage 4: Decode embedded strings
# Use CyberChef for Base64, hex, XOR patterns found in code
```

### Python Analysis

**PyInstaller / Frozen Python:**
```bash
# Extract .pyc files from PyInstaller bundle
# Use Arkana's auto_unpack_pe if it's a PE-wrapped PyInstaller
# Or manually:
pip install pyinstxtractor
python pyinstxtractor.py <target.exe>
# Output: <target.exe>_extracted/ directory with .pyc files
```

**PYC Decompilation (version-dependent):**

| Python Version | Tool | Install |
|---------------|------|---------|
| 2.7 | uncompyle6 | `pip install uncompyle6` |
| 3.0 - 3.8 | uncompyle6 | `pip install uncompyle6` |
| 3.9 - 3.12 | decompyle3 / pycdc | `pip install decompyle3` or build pycdc from source |
| 3.13+ | pycdc | Build from source (github.com/zrax/pycdc) |

```bash
# Decompile .pyc
uncompyle6 <file.pyc> > <file.py>
# Or for newer Python:
decompyle3 <file.pyc> > <file.py>
```

**Obfuscated Python source:**
- **PyArmor**: Look for `__pyarmor__` markers, encrypted bytecode blobs
- **Cython-compiled**: `.pyd`/`.so` files — treat as native binary, use Ghidra
- **Base64/exec chains**: Decode iteratively with CyberChef
- **pyobfuscate / pyminifier**: Usually just variable renaming — beautify and analyze

**Marshal/bytecode analysis:**
```python
# For custom bytecode manipulation:
import dis, marshal
with open('file.pyc', 'rb') as f:
    f.read(16)  # skip header (size varies by Python version)
    code = marshal.load(f)
    dis.dis(code)
```

### Protocol Reverse Engineering

**Step 1: Capture**
```bash
# If Wireshark installed:
"${TSHARK_PATH:-C:/Program Files/Wireshark/tshark.exe}" -r capture.pcap -z follow,tcp,raw,0 > stream.raw
"${TSHARK_PATH:-C:/Program Files/Wireshark/tshark.exe}" -r capture.pcap --export-objects http,./exported/

# Or use tcpdump on Linux/WSL:
tcpdump -i eth0 -w capture.pcap host <target>
```

**Step 2: Identify wire format**

Use CyberChef MCP to decode raw bytes:
- Look for **magic bytes** at stream start
- Check for **length-prefixed** messages (first 2/4 bytes = message length)
- Check for **type tags** (byte after length = message type)
- Check for **delimiter framing** (newline, null, CRLF)
- Try common formats: protobuf (varint encoding), msgpack, JSON, ASN.1 (DER/BER)

**Step 3: Map message structure**

For each message type:
```markdown
| Offset | Size | Field | Type | Notes |
|--------|------|-------|------|-------|
| 0x00 | 4 | magic | uint32_be | Always 0xDEADBEEF |
| 0x04 | 2 | length | uint16_be | Total message length |
| 0x06 | 1 | type | uint8 | Message type identifier |
```

**Step 4: Correlate with binary**
- Find protocol handler in Ghidra: search for magic bytes, `recv()`/`send()` xrefs
- Decompile parsing functions to confirm field types
- Use codebadger `get_variable_flow` to trace from recv() to parser

**Step 5: Document** protocol specification as you discover it.

### Memory Forensics

Delegate to `/forensics` skill for full workflow. Quick reference:

```bash
vol -f <dump> windows.info       # OS info
vol -f <dump> windows.pslist     # running processes
vol -f <dump> windows.pstree     # process tree
vol -f <dump> windows.malfind    # injected/suspicious code sections
vol -f <dump> windows.netscan    # connections and listeners
vol -f <dump> windows.dumpfiles --pid <pid>  # extract files
```

---

## Cross-Cutting Techniques

### String Decryption
1. Identify decryption routine (Ghidra decompile)
2. Use CyberChef to replicate: XOR, Base64, AES-CBC, RC4, custom
3. Batch decrypt all strings to build a string table

### Control Flow Recovery
1. Use codebadger `get_cfg` for control flow graph
2. Use Ghidra function graph view
3. Use Arkana's angr symbolic execution for path exploration
4. Use capa to identify obfuscation techniques used

---

## Output Format

```markdown
# RE Analysis: [Target Name]

## Target Info
- File: [name], Size: [size], Type: [PE/ELF/APK/etc.]
- MD5: [hash] | SHA256: [hash]
- Architecture: [x86/x64/ARM/MIPS]
- Language: [C/C++/Go/Rust/.NET/Java/Python/JS]
- Source/context: [how obtained]

## Triage Summary
- Packer/protector: [detected or none]
- Language/framework: [identified]
- Compiler: [if detected]
- YARA matches: [signatures with confidence]
- capa capabilities: [ATT&CK mappings]
- Notable strings: [top ranked by stringsifter]

## Detailed Analysis
[Function-by-function or component-by-component]
- Confidence level for each conclusion: HIGH/MEDIUM/LOW

## Indicators of Compromise (if malware)
- **Network**: C2 domains, IPs, URLs, user agents
- **Host**: files created, registry keys, mutexes, services, scheduled tasks
- **Behavioral**: ATT&CK techniques observed

## Artifacts
- Decompiled code: [paths]
- Extracted strings: [path to string table]
- Screenshots: [paths]

## Conclusions
[What the software does, how it works]
- Can another analyst reproduce this analysis? [yes/no + instructions]
```
