# Reverse Engineering Tool Paths Reference

## MCP Servers (auto-connected via .claude.json)
- ghydramcp: Ghidra bridge at C:\Users\slabl\Tools\GhydraMCP (requires Ghidra running with plugin loaded)
- arkana: docker run --rm -i arkana:latest --mcp-server --mcp-transport stdio (250+ tools, 5.7GB image)
- codebadger: http://localhost:4242/mcp (start: cd C:/Users/slabl/Documents/Projects/codebadger && docker compose up -d && .venv/Scripts/python.exe main.py)
- cyberchef: node C:/Users/slabl/Tools/CyberChef-MCP/src/node/mcp-server.mjs
- deobfuscate-mcp: node C:/Users/slabl/Tools/deobfuscate-mcp-server/dist/index.js

## Decompilers
- JADX (Java/Android): C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat
- ILSpy (.NET, GUI): C:/Users/slabl/Tools/ilspy/ILSpy/ILSpy.exe
- RetDec (native -> C): C:/Users/slabl/Tools/retdec/retdec-v5.0/bin/retdec-decompiler.exe

## Deobfuscators
- webcrack: webcrack (global npm) — JS obfuscator.io + webpack
- synchrony: synchrony (global npm) — JS javascript-obfuscator
- prettier: npx prettier (global npm) — JS beautifier

## Docker Containers (start: cd C:/Users/slabl/Tools/mcp-security-hub && docker compose up <name> -d)
- yara-mcp: signature matching
- capa-mcp: capability analysis + MITRE ATT&CK mapping
- binwalk-mcp: firmware extraction + entropy analysis
- radare2-mcp: multi-arch disassembly + scripted analysis
- virustotal-mcp: hash/sample lookup (needs API key)

## CLI Tools
- Volatility 3: vol (system pip) — memory forensics
- Frida: frida / frida-ps / frida-trace (system pip) — dynamic instrumentation
- Joern CLI: C:/Users/slabl/Tools/joern/joern-cli/joern
- tshark (if Wireshark installed): C:\Program Files\Wireshark\tshark.exe
