# NEXUS - Pentest LLM with MCP Tool Calling

## Original Problem Statement
Create a fully formed local pentest LLM with Kali MCP tool calling and local MCP file access.

## User Choices
- **LLM Provider**: GPT-5.2 with Emergent LLM Key (free option)
- **Kali Tools**: Full scope - 99+ tools across 11 categories
- **File Access**: All operations - read, write, list, delete, execute
- **UI**: Modern GUI with hacker aesthetic
- **Auto-Execute**: 5-second countdown with pause/skip/cancel
- **Disclaimer**: Authorization confirmation before proceeding

## Architecture

### Backend (FastAPI)
- `/api/chat` - AI-powered pentest assistant using GPT-5.2 (autonomous mode)
- `/api/tools` - 99+ Kali tool definitions across 11 categories
- `/api/tools/execute` - Simulated tool execution with realistic outputs
- `/api/workflows` - Pre-defined attack workflows (10 workflows)
- `/api/workflows/execute` - Chain multiple tools automatically
- `/api/vulnerabilities/*` - Vulnerability database and correlation
- `/api/export/report` - Export session results
- `/api/sessions` - Chat session management
- `/api/files/*` - MCP file system operations (sandboxed)

### Frontend (React)
- **Disclaimer Modal**: Authorization confirmation
- **Quick Actions Bar**: Target input + 10 workflow buttons
- **Sidebar**: Session management
- **Chat Interface**: Autonomous AI assistant
- **Tools Panel**: 99+ tools with auto-execute (5s countdown)
- **Terminal Output**: Real-time tool execution results
- **File Explorer**: MCP file system browser

### Tool Categories (99+ Tools)
1. **Network (9)**: nmap, netcat, masscan, wireshark, ettercap, responder...
2. **Web (10)**: nikto, sqlmap, dirb, gobuster, ffuf, xsstrike, commix...
3. **Password (8)**: hydra, john, hashcat, mimikatz, medusa, crunch...
4. **Exploitation (7)**: metasploit, empire, cobalt-strike, covenant...
5. **Wireless (6)**: aircrack-ng, wifite, kismet, bettercap...
6. **Recon (10)**: whois, theHarvester, subfinder, amass, spiderfoot...
7. **Forensics (7)**: volatility, autopsy, binwalk, sleuthkit...
8. **Social (4)**: setoolkit, gophish, evilginx2...
9. **Exfiltration (10)**: dnscat2, chisel, cloakify, iodine, ptunnel...
10. **Post-Exploit (12)**: bloodhound, mimikatz, linpeas, winpeas, lazagne, rubeus...
11. **Pivoting (6)**: sshuttle, ligolo, proxychains, rpivot...

### Workflows
1. Quick Recon - Fast assessment
2. Web App Audit - Web security scan
3. Network Sweep - Network enumeration
4. Credential Audit - Password testing
5. AD Attack - Active Directory chain
6. Exfil Setup - Data exfiltration
7. Linux PE - Linux privilege escalation
8. Windows PE - Windows privilege escalation
9. Lateral Movement - Network pivoting
10. Full Pentest - Complete assessment

## What's Been Implemented (Jan 2026)
- [x] Disclaimer modal with authorization confirmation
- [x] AI chat with GPT-5.2 (autonomous mode - no ethical warnings)
- [x] 99+ Kali tools across 11 categories
- [x] Tool auto-execute with 5-second countdown
- [x] 10 pre-defined attack workflows
- [x] Simulated tool execution with realistic outputs
- [x] Session persistence with MongoDB
- [x] MCP file system sandbox
- [x] Vulnerability database and correlation
- [x] Report export functionality
- [x] Post-exploitation tools (BloodHound, Mimikatz, etc.)
- [x] Exfiltration tools (DNScat2, Chisel, Cloakify, etc.)
- [x] Pivoting tools (SSHuttle, Ligolo, etc.)

## Note
All tool execution is **SIMULATED** for safety. Outputs are realistic but no actual network scanning or exploitation occurs.
