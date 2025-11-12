<div align="center">

<pre>
███████╗██╗██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
█████╗  ██║██████╔╝█████╗  ███████╗██║     ███████║██╔██╗ ██║
██╔══╝  ██║██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ██║██║  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
</pre>

# FireScan

**Automated security testing for Firebase applications**

[![Release](https://img.shields.io/github/v/release/JacobDavidAlcock/firescan)](https://github.com/JacobDavidAlcock/firescan/releases)
[![License](https://img.shields.io/github/license/JacobDavidAlcock/firescan)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/JacobDavidAlcock/firescan)](go.mod)
[![Build Status](https://github.com/JacobDavidAlcock/firescan/workflows/Test/badge.svg)](https://github.com/JacobDavidAlcock/firescan/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/JacobDavidAlcock/firescan)](https://goreportcard.com/report/github.com/JacobDavidAlcock/firescan)

<img src="demo.gif" alt="FireScan Demo" width="800px">

</div>

## Overview

Interactive security auditing tool for Firebase. Automatically enumerates and tests Realtime Database, Firestore, Cloud Storage, Cloud Functions, and Authentication.

**Features:**
- Interactive console with command history
- Concurrent scanning (1-1000 workers)
- Automatic JWT refresh
- Built-in wordlists with case variations
- Three safety modes: probe (read-only), test (safe writes), audit (deep testing)
- JSON output

## Quick Start

**Install:**
```bash
# Using Go
go install github.com/JacobDavidAlcock/firescan/cmd/firescan@latest

# Or download binary
https://github.com/JacobDavidAlcock/firescan/releases/latest
```

**Usage:**
```bash
firescan
> set projectID your-firebase-app
> set apiKey AIzaSy...
> auth --create-account
> scan --all
```

## Commands

**Authentication:**
```bash
auth --create-account              # Create test account
auth -e user@email.com -P pass     # Login with credentials
auth --enum-providers              # Enumerate auth providers
auth logout                        # Clear session
```

**Scanning:**
```bash
scan --all                         # Scan all services
scan --rtdb --firestore            # Specific services
scan --unauth                      # Test without authentication
scan --all -c 100 --rate-limit 50  # 100 workers, 50 req/s
scan --all --json                  # JSON output
```

**Data Extraction:**
```bash
extract --firestore --path users
extract --rtdb --path /admin/config
extract --firestore --path users --output data.json
```

**Wordlists:**
```bash
wordlist show                      # List available wordlists
wordlist show users                # View wordlist contents
wordlist add custom admin,secret   # Create custom wordlist
```

Built-in wordlists: `users`, `config`, `passwords`, `functions`, `database`, `storage`, `security`, `all`

## Service Coverage

| Service | Capabilities |
|---------|-------------|
| **Realtime Database** | Node enumeration, read access testing, root exposure detection |
| **Firestore** | Collection discovery, document enumeration, permission testing |
| **Cloud Storage** | Bucket listing, file enumeration, ACL testing |
| **Cloud Functions** | Function discovery across 7 regions, auth validation |
| **Authentication** | Provider enumeration, JWT testing, token validation |

## Safety Modes

```
🟢 PROBE (default)  → Read-only operations
🟡 TEST             → Safe write tests with cleanup
🔴 AUDIT            → Deep testing (requires confirmation)
```

## Installation

**Linux:**
```bash
curl -sL https://github.com/JacobDavidAlcock/firescan/releases/latest/download/firescan-linux-amd64.tar.gz | tar xz
sudo mv firescan /usr/local/bin/
```

**macOS:**
```bash
curl -sL https://github.com/JacobDavidAlcock/firescan/releases/latest/download/firescan-darwin-amd64.tar.gz | tar xz
sudo mv firescan /usr/local/bin/
```

**Windows:**
Download from [releases](https://github.com/JacobDavidAlcock/firescan/releases/latest), extract, and add to PATH.

**From Source:**
```bash
git clone https://github.com/JacobDavidAlcock/firescan.git
cd firescan
go build -o firescan cmd/firescan/main.go
```

## Examples

**Penetration Testing:**
```bash
> set projectID target-app
> auth --create-account
> scan --all --json > findings.json
```

**Pre-deployment Check:**
```bash
> scan --unauth
> scan --rules
```

**Bug Bounty:**
```bash
> scan --all -c 100 --rate-limit 50
> extract --firestore --path users --output evidence.json
```

## Comparison

| Feature | FireScan | Manual Testing | Firebase Emulator |
|---------|----------|----------------|-------------------|
| Speed | ~2 minutes | 20+ minutes | N/A |
| Automation | Full | Manual | Partial |
| Service Coverage | All services | All services | Limited |
| Production Testing | ✅ Safe | ⚠️ Risky | ❌ Dev only |

## Roadmap

**Current (v2.1.0)**
- Full service scanning (RTDB, Firestore, Storage, Functions, Auth)
- Three safety modes
- Session management and auto-refresh
- Custom wordlists and JSON output

**Next (v2.2.0)**
- Cleanup implementation
- HTML/PDF report generation
- Enhanced error reporting

**Planned (v3.0.0)**
- Firebase rules analyzer
- Multi-project scanning
- CI/CD integration
- Continuous monitoring mode

## Legal

⚠️ **FireScan is for authorized security testing only.** Unauthorized testing is illegal.

## License

MIT License - see [LICENSE](LICENSE)

---

<div align="center">

**Made by [Jacob Alcock](https://jacobalcock.co.uk)**

[Website](https://jacobalcock.co.uk) • [LinkedIn](https://www.linkedin.com/in/jacob-alcock/) • [Blog](https://blog.jacobalcock.co.uk)

</div>
