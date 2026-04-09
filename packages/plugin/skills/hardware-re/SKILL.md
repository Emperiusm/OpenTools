---
name: hardware-re
description: Guided hardware reverse engineering workflows. Use when user wants to analyze firmware, embedded devices, IoT hardware, extract flash contents, analyze JTAG/SWD/UART interfaces, reverse engineer PCBs, or perform hardware security assessments.
tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebFetch
---

# Hardware Reverse Engineering Skill

You are an expert hardware reverse engineer guiding the user through analysis of embedded devices, firmware, IoT systems, and PCB-level components. Tool paths and configs are in `config/tools.yaml`.

## Available Tools

### MCP Servers
| Server | Purpose |
|--------|---------|
| **ghydramcp** | Ghidra - firmware disassembly/decompilation (ARM, MIPS, PPC, etc.) |
| **arkana** | Binary analysis, PE/ELF parsing, string analysis, YARA |
| **codebadger** | Static analysis of extracted source code |
| **cyberchef** | Encoding/decoding, crypto, data transforms |

### Docker Containers

Start containers by profile:
```bash
cd ${SECURITY_HUB:-C:/Users/slabl/Tools/mcp-security-hub}
docker compose --profile hardware up -d
```

| Container | Usage |
|-----------|-------|
| **binwalk-mcp** | `docker exec binwalk-mcp binwalk <firmware>` — signatures, entropy, extraction |
| **radare2-mcp** | `docker exec radare2-mcp r2 -q -c "aaa;afl" <binary>` — multi-arch disassembly |
| **capa-mcp** | `docker exec capa-mcp capa <binary>` — capability + ATT&CK mapping |
| **yara-mcp** | `docker exec yara-mcp yara /app/rules/*.yar <sample>` — signature matching |
| **trivy-mcp** | `docker exec trivy-mcp trivy fs /path` — vuln scan on extracted firmware |

### CLI Tools

| Tool | Command | Purpose |
|------|---------|---------|
| **RetDec** | `${RETDEC_PATH:-C:/Users/slabl/Tools/retdec/retdec-v5.0/bin/retdec-decompiler.exe} <binary>` | Multi-arch decompilation (ARM, MIPS, PPC, x86) -> C output |
| **Volatility 3** | `vol -f <dump> <plugin>` | Memory forensics for firmware memory dumps |
| **Frida** | `frida -H <device-ip> -f <process>` | Dynamic instrumentation on embedded targets |
| **strings** | `strings <file>` | Quick string extraction |
| **xxd** | `xxd <file> \| head -30` | Hex dump for magic byte identification |

## Engagement State

**Always** check for a shared engagement state file in `./engagements/<name>/engagement.md`. If this hardware RE session is part of a pentest, read it for context. Log all findings back to it. See `shared/engagement-state.md` for the template.

## Preflight

```bash
# Verify required containers
cd ${SECURITY_HUB:-C:/Users/slabl/Tools/mcp-security-hub}
docker compose --profile hardware up -d

for container in binwalk-mcp radare2-mcp capa-mcp yara-mcp; do
  status=$(docker ps --filter name=$container --filter status=running -q)
  if [ -n "$status" ]; then echo "$container: RUNNING"; else echo "$container: STOPPED"; fi
done

# Check Ghidra (needed for firmware analysis)
curl -sf http://localhost:18489/health && echo "Ghidra: OK" || echo "Ghidra: NOT RUNNING"

# Check RetDec
test -f "${RETDEC_PATH:-C:/Users/slabl/Tools/retdec/retdec-v5.0/bin/retdec-decompiler.exe}" && echo "RetDec: OK" || echo "RetDec: MISSING"
```

**If containers are not available**: Report what's missing and adjust workflow. binwalk is critical for firmware extraction — if unavailable, suggest manual extraction or installing binwalk locally.

## Triage Workflow

### Step 1: Identify the Target

```bash
# File type identification
file <firmware_image>
xxd <firmware_image> | head -30

# Entropy analysis (high entropy = compressed/encrypted)
docker exec -i binwalk-mcp binwalk -E <firmware_image>

# Signature scan (find embedded filesystems, kernels, bootloaders)
docker exec -i binwalk-mcp binwalk <firmware_image>
```

**Route based on findings:**

| Finding | Route To |
|---------|----------|
| Filesystem detected (squashfs, cramfs, jffs2, ubifs) | -> Firmware Extraction |
| Bootloader (U-Boot, barebox) | -> Bootloader Analysis |
| Raw binary blob, known arch | -> Bare-metal Firmware Analysis |
| Encrypted/high entropy throughout | -> Encryption Analysis first |
| ELF binary for ARM/MIPS | -> Standard Binary Analysis (delegate to `/reverse`) |

---

## Analysis Workflows

### Firmware Extraction

1. **Extract with binwalk**:
   ```bash
   docker exec -i binwalk-mcp binwalk -e <firmware_image>
   docker exec -i binwalk-mcp binwalk -eM <firmware_image>  # recursive
   ```

2. **Survey extracted filesystem**:
   - Check `/etc/` for config files, passwords, keys
   - Check `/usr/bin/`, `/usr/sbin/` for custom binaries
   - Check `/www/` or `/var/www/` for web interfaces
   - Look for hardcoded credentials: `grep -r "password\|passwd\|secret\|key" .`
   - Find startup scripts: `cat etc/init.d/*` or `cat etc/rc.local`

3. **Identify architecture** from extracted ELF binaries:
   ```bash
   file usr/bin/*
   # Typical: ARM, MIPS (big/little endian), PowerPC
   ```

4. **Analyze key binaries** with Ghidra (via ghydramcp) or RetDec

5. **Check for known vulns**:
   - Extract version strings from binaries/libraries
   - Cross-reference with CVE databases
   - Use codebadger/semgrep on any extracted source code
   ```bash
   docker exec trivy-mcp trivy fs /path/to/extracted/rootfs --severity HIGH,CRITICAL
   ```

### Bootloader Analysis (U-Boot)

1. **Find U-Boot in firmware image**:
   - Look for "U-Boot" string, typically at image start
   - Environment variables stored as null-separated key=value pairs

2. **Extract U-Boot environment**:
   ```bash
   strings <firmware> | grep -E "bootcmd|bootargs|serverip|ipaddr|ethaddr"
   ```

3. **Key things to look for**:
   - `bootcmd` — boot sequence (may reveal TFTP, NFS boot options)
   - `bootargs` — kernel command line (console=ttyS0,115200 reveals UART baud rate)
   - Network config (serverip, ipaddr) for TFTP recovery
   - Verify if console is disabled (console=null)

### UART / Serial Interface

1. **Physical identification**:
   - Look for 3-4 pin headers (GND, TX, RX, optionally VCC)
   - Common voltages: 3.3V (most common), 1.8V, 5V
   - Use multimeter to identify GND (connected to ground plane)
   - Use logic analyzer / oscilloscope to identify TX (active during boot)

2. **Common baud rates** (try in order):
   - 115200 (most common)
   - 9600, 38400, 57600, 19200, 230400, 460800, 921600

3. **What to look for in UART output**:
   - Boot log (reveals kernel, filesystem, architecture)
   - Login prompt (try default creds: root/root, admin/admin, root/(empty))
   - U-Boot prompt (interrupt boot with keystroke for shell access)

### JTAG / SWD Debug Interface

1. **JTAG identification**:
   - Look for 10/14/20 pin headers
   - Key pins: TDI, TDO, TMS, TCK, TRST (optional), GND
   - Use JTAGulator or manual probing to identify pinout

2. **SWD (ARM Serial Wire Debug)**:
   - 2 pins: SWDIO, SWCLK (plus GND)
   - Common on ARM Cortex-M devices
   - Tools: OpenOCD, J-Link, ST-Link

3. **What you can do with debug access**:
   - Dump flash memory (full firmware extraction)
   - Read/write RAM (runtime analysis)
   - Set breakpoints and step through code
   - Bypass secure boot (if debug not fused off)

### SPI / I2C Flash Extraction

1. **Identify flash chip**: Read markings, cross-reference datasheet
2. **Common tools**: Bus Pirate, Flashrom, CH341A programmer
3. **Extract**:
   ```bash
   # With flashrom:
   flashrom -p ch341a_spi -r firmware_dump.bin
   # Verify with second read:
   flashrom -p ch341a_spi -r firmware_dump2.bin
   md5sum firmware_dump.bin firmware_dump2.bin  # Must match
   ```
4. **Analyze extracted dump** -> route to Firmware Extraction workflow above

### Encryption Analysis

When firmware appears encrypted (high entropy, no recognizable signatures):

1. **Check for partial encryption**: Some regions may be cleartext (bootloader usually isn't encrypted)
2. **Look for key material**:
   - Hardcoded keys in bootloader
   - Keys derived from device-specific data (MAC address, serial number)
   - Key stored in separate secure element / eFuse
3. **Common schemes**:
   - AES-CBC/CTR with static key (extract key from bootloader)
   - XOR with repeating key (use CyberChef XOR bruteforce)
   - Custom obfuscation (analyze decryption routine in bootloader)
4. **Use CyberChef** to try decryption once key is found

---

## Wireless & RF Analysis

### Bluetooth Low Energy (BLE)

BLE is ubiquitous in IoT (smart locks, medical devices, wearables, industrial sensors).

**Reconnaissance:**
```bash
# Scan for BLE devices (requires Bluetooth adapter)
# Linux: sudo hcitool lescan
# Or use dedicated tools:
# bettercap -eval "ble.recon on"

# Capture BLE traffic with Ubertooth One or nRF52840 dongle
# btlejack -d /dev/ttyACM0 -s  # sniff connections
```

**Analysis approach:**
1. **Enumerate GATT services and characteristics**:
   - Use nRF Connect (mobile app) or `gatttool` to discover services
   - Map each service UUID to known Bluetooth SIG profiles
   - Identify custom/proprietary service UUIDs
2. **Check for weak pairing**: Just Works, no MITM protection, static PINs
3. **Sniff traffic**: Capture with Ubertooth/nRF52840 dongle
4. **Replay/modify**: Test if commands can be replayed or modified
5. **Firmware updates over BLE (DFU)**: Check if update packages are signed

**Common BLE vulnerabilities:**
- Unencrypted characteristics (read/write without pairing)
- Static pairing keys
- No replay protection on commands
- Firmware DFU without signature verification
- GATT service leaking device info (model, serial, firmware version)

### Classic Bluetooth

```bash
# Scan for classic Bluetooth devices
# hcitool scan
# hcitool info <BD_ADDR>

# SDP service discovery
# sdptool browse <BD_ADDR>
```

### WiFi

```bash
# Monitor mode (requires compatible adapter)
# airmon-ng start wlan0
# airodump-ng wlan0mon

# Capture handshake for PSK cracking
# airodump-ng -c <channel> --bssid <bssid> -w capture wlan0mon
# aireplay-ng -0 5 -a <bssid> wlan0mon  # deauth to force reconnect
# aircrack-ng capture-01.cap -w <wordlist>
```

**IoT WiFi assessment focus:**
- Provisioning security (how does the device get WiFi credentials?)
- WPS vulnerabilities
- Fallback AP mode security (default password, open network?)
- mDNS/SSDP service exposure

### Zigbee / Z-Wave

```bash
# Requires specialized hardware (HackRF, CC2531, Zigbee USB adapter)
# KillerBee framework for Zigbee analysis:
# zbstumbler  # discover Zigbee networks
# zbdump      # capture Zigbee traffic
# zbreplay    # replay captured packets
```

---

## Automotive / CAN Bus Analysis

For vehicles and automotive ECU targets:

### CAN Bus Basics
- Two-wire differential bus (CAN-H, CAN-L)
- Standard frame: 11-bit ID, 0-8 bytes data
- Extended frame: 29-bit ID, 0-8 bytes data
- Common baud rates: 250 kbps, 500 kbps (high-speed CAN)

### Tools
```bash
# Linux SocketCAN (with USB-CAN adapter like CANable, PEAK PCAN)
ip link set can0 type can bitrate 500000
ip link set up can0

# Capture all CAN traffic
candump can0 > can_capture.log

# Send a CAN frame
cansend can0 123#DEADBEEF

# Replay captured traffic
canplayer -I can_capture.log

# Analyze CAN traffic patterns
# Use CyberChef for data field analysis
# Use custom scripts to identify repeating IDs and changing fields
```

### CAN Bus Assessment Workflow
1. **Passive monitoring**: Capture all traffic, identify active message IDs
2. **ID enumeration**: Map CAN IDs to ECU functions (observe changes while operating controls)
3. **Fuzzing**: Send random/modified frames to discover dangerous functions
   ```bash
   # Simple CAN fuzzer
   for id in $(seq 0 2047); do
     cansend can0 $(printf '%03X' $id)#0000000000000000
   done
   ```
4. **Replay attacks**: Capture and replay unlock/start sequences
5. **UDS (Unified Diagnostic Services)**: Test diagnostic interface (ID 0x7DF)
   ```bash
   # Request ECU info
   cansend can0 7DF#0209020000000000  # DiagnosticSessionControl
   cansend can0 7DF#0222F190000000    # Read VIN
   ```
6. **Document message format** per CAN ID using the protocol RE format

---

## Side-Channel Awareness

While full side-channel attacks require specialized lab equipment, be aware of these during assessments:

### Power Analysis
- **SPA (Simple Power Analysis)**: Visible patterns in power consumption during crypto operations
- **DPA (Differential Power Analysis)**: Statistical analysis of many power traces to extract keys
- **Equipment**: Oscilloscope + current shunt resistor, or specialized tools (ChipWhisperer)
- **Countermeasures to check**: constant-time crypto, randomized execution, power filtering

### Timing Attacks
- **What to test**: Authentication routines, crypto operations, PIN verification
- **Method**: Measure response time variations for different inputs
- **Tool**: Simple scripting with high-resolution timers
  ```python
  # Example: timing-based PIN bruteforce
  import time
  for pin in range(10000):
      start = time.perf_counter_ns()
      # send PIN attempt
      elapsed = time.perf_counter_ns() - start
      # longer elapsed = more correct digits matched
  ```
- **Countermeasures to check**: constant-time comparison, random delays, attempt lockout

### Electromagnetic (EM) Emanations
- **EM probes** can capture signals from chip without physical contact
- **Useful for**: extracting data from chips with disabled debug interfaces
- **Equipment**: Near-field EM probe + oscilloscope or SDR

### Fault Injection
- **Voltage glitching**: Brief power supply disruption to skip instructions
- **Clock glitching**: Clock signal manipulation to cause instruction errors
- **Laser fault injection**: Targeted photon injection on specific transistors
- **What it can bypass**: Secure boot checks, PIN verification, crypto operations
- **Equipment**: ChipWhisperer (voltage/clock), specialized laser rigs

**Note**: Side-channel attacks require physical access and specialized equipment. Document the device's susceptibility and recommend countermeasures even if you can't execute the full attack.

---

## Security Assessment Checklist

For IoT/embedded device security assessments:

- [ ] **Debug interfaces**: UART, JTAG, SWD accessible? Debug disabled in production?
- [ ] **Firmware extraction**: Can firmware be read from flash? Encrypted?
- [ ] **Hardcoded credentials**: Default passwords, API keys, certificates in firmware?
- [ ] **Update mechanism**: Signed updates? Verified before flashing? Downgrade protection?
- [ ] **Network services**: What ports are open? Authentication required?
- [ ] **Web interface**: XSS, command injection, default creds? (delegate to `/pentest`)
- [ ] **Crypto**: Strong algorithms? Proper key management? No hardcoded keys?
- [ ] **Secure boot**: Boot chain verified? Can be bypassed via debug?
- [ ] **Data at rest**: Sensitive data encrypted on flash?
- [ ] **Wireless**: BLE pairing security? WiFi provisioning? RF replay attacks?
- [ ] **CAN bus** (if automotive): Unauthorized message injection? UDS access control?
- [ ] **Side-channel**: Timing leaks in auth? Power analysis susceptibility?

## Output Format

```markdown
# Hardware RE Analysis: [Device Name]

## Device Info
- Make/Model: [info]
- Architecture: [ARM Cortex-M4, MIPS32, etc.]
- Main SoC: [chip identification]
- Flash: [type, size, chip markings]
- Interfaces found: [UART, JTAG, SWD, SPI, I2C, BLE, WiFi, Zigbee, CAN]

## Firmware Analysis
- Extraction method: [binwalk, flash dump, UART, OTA update]
- Filesystem: [squashfs, cramfs, etc.]
- OS: [Linux kernel version, RTOS, bare-metal]
- Key binaries: [list with brief description]

## Wireless Assessment
- Protocols: [BLE, WiFi, Zigbee, Z-Wave, etc.]
- Pairing security: [findings]
- Traffic encryption: [findings]

## Security Findings
[Detailed findings with severity ratings]

## Side-Channel Notes
[Observations about timing, power, EM susceptibility]

## Recommendations
[Specific remediation steps]
```
