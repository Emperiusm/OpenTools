# Hardware RE Tool Paths Reference

## MCP Servers
- ghydramcp: Ghidra bridge (requires Ghidra running with GhydraMCP at C:\Users\slabl\Tools\GhydraMCP)
- arkana: docker run --rm -i arkana:latest --mcp-server --mcp-transport stdio
- codebadger: http://localhost:4242/mcp (requires CodeBadger server running)
- cyberchef: node C:/Users/slabl/Tools/CyberChef-MCP/src/node/mcp-server.mjs

## Docker Containers (start with: cd C:/Users/slabl/Tools/mcp-security-hub && docker compose up <name> -d)
- binwalk-mcp: Firmware extraction, entropy analysis, signature scanning
- radare2-mcp: Multi-arch disassembly and analysis
- capa-mcp: Capability analysis, MITRE ATT&CK mapping
- yara-mcp: Signature matching
- trivy-mcp: Vulnerability scanning on extracted firmware

## CLI Decompilers
- RetDec: C:/Users/slabl/Tools/retdec/retdec-v5.0/bin/retdec-decompiler.exe
- JADX: C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat (for embedded Android)

## CLI Tools
- Volatility 3: vol (system pip) — memory forensics
- Frida: frida / frida-tools (system pip) — dynamic instrumentation
- strings: system tool
- xxd: system tool (via Git Bash)
