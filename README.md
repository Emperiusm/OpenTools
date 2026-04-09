# Security Skills Plugin

Pentesting and Reverse Engineering skills for Claude Code.

## Skills

- **pentest** - Guided penetration testing workflows (recon, scanning, exploitation, post-exploitation, reporting)
- **reverse-engineering** - Binary/source/web reverse engineering and deobfuscation workflows

## Commands

- `/pentest` - Start a pentest engagement
- `/reverse` - Start a reverse engineering session

## Required MCP Servers

- codebadger (Joern static analysis)
- cyberchef (encoding/decoding/crypto)
- semgrep-mcp (vulnerability scanning)
- nmap-mcp (network recon)
- arkana (binary analysis)
- ghydramcp (Ghidra RE)
- deobfuscate-mcp (JS deobfuscation)
- wazuh-mcp (SIEM/threat hunting)
- elasticsearch-mcp (log analysis)

## CLI Tools on PATH

- webcrack, synchrony (JS deobfuscation)
- jadx (Java/Android decompilation)
- ILSpy (. NET decompilation)
- retdec-decompiler (binary decompilation)
- sliver-server (C2 framework)
- pydecipher (Python deobfuscation)
