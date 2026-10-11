# 🛡️ TermuxSentinel

A colorful, defensive security toolkit for **Termux on Android**. Pure Python 3, **standard library only**: no pip packages, no root.

> ⚠️ For education and **authorized** security auditing only. Read [DISCLAIMER.md](DISCLAIMER.md) before use.

## Features

| # | Module | Description |
|---|--------|-------------|
| 1 | **HTTP Header Audit** | Checks 7 security headers (HSTS, CSP, X-Frame-Options, ...), flags information-leaking headers and weak cookie flags, and gives a 0-100 score with an A-F grade |
| 2 | **TLS Inspector** | Verifies the certificate chain; shows subject, issuer, SANs, expiry, protocol and cipher; warns on expiry or legacy TLS |
| 3 | **DNS Resolver** | A / AAAA / alias records and reverse lookups |
| 4 | **Authorized Port Checker** | TCP connect check of up to 100 ports (30 common by default), 10 threads, flags risky exposed services. Requires typing `I AUTHORIZE` |
| 5 | **Device Network Info** | Hostname, local IP and subnet guess. Fully offline |
| 6 | **JSON Reports** | Saves session results to `~/sentinel_reports/` |

Also included: ANSI-colored menu, graceful error handling, `--no-color` flag, and a first-run consent screen.

## Requirements

- Termux (Android 7+), installed from [F-Droid](https://f-droid.org/packages/com.termux/)
- Python 3.7+ (installed automatically by `install.sh`)
- Internet access for modules 1-4 (module 5 works offline)

## Installation (Termux)

### 1. Install Git

```bash
pkg update -y && pkg install -y git
```

### 2. Clone the repository

```bash
git clone 
```

### 3. Run the installer

```bash
cd Termux-Sentinel
bash install.sh
```

The installer updates `pkg`, installs Python, makes the scripts executable, and creates a `sentinel` launcher command.

### 4. Launch

```bash
sentinel
```

Or run it directly:

```bash
python3 main.py
```

### Update to the latest version

```bash
cd ~/TermuxSentinel
git pull
```

### Manual install (without the script)

```bash
pkg install -y python
python3 main.py
```

## Usage

```bash
sentinel              # start the interactive menu
sentinel --no-color   # plain output (no ANSI colors)
sentinel --version    # print version
```

Choose a number from the menu and follow the prompts:

- **Header audit:** enter `example.com` or `https://example.com`
- **Port check:** enter a host you own, type `I AUTHORIZE`, then press Enter for the default list or give `22,80,443`
- **Reports:** choose option 6, or answer `y` when exiting, to write a JSON file

Sample report excerpt:

```json
{
  "module": "header_audit",
  "target": "example.com",
  "data": { "score": 35, "grade": "F", "missing": [ "..." ] }
}
```

## Project structure

```
TermuxSentinel/
├── main.py         # application
├── install.sh      # Termux setup script
├── README.md
└── DISCLAIMER.md
```
).

## Disclaimer.md
Use only on systems you own or have explicit written permission to test. See [DISCLAIMER.md](DISCLAIMER.md).
