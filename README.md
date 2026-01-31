# Yelbegen - Passive OSINT Scanner

Yelbegen is a professional passive OSINT reconnaissance tool that performs comprehensive scanning of domains and IP addresses using multiple intelligence sources.

## Features

- **Three Scanning Modes:**
  - **Basic Mode**: Fast modular scanning with 6 free intelligence sources
  - **Full Mode** (`-f`): Enhanced UI with clickable links + 7 scanners
  - **API Mode** (`-a`): Premium intelligence with VirusTotal, SecurityTrails, Shodan, URLScan

- **Passive Reconnaissance**: All information gathered from public databases
- **Multiprocessing**: True parallel execution for maximum speed
- **Rich Terminal UI**: Beautiful, live-updating interface
- **Optional API Support**: Works without keys, enhanced with them

## Quick Start

### Installation

```bash
# Option 1: Using pipx (recommended)
sudo apt install pipx
pipx ensurepath
# Reopen terminal
cd yelbegen-main
./reinstall.sh

# Option 2: Using pip (bypass system packages)
./reinstall.sh --system
```

### Basic Usage

```bash
# Basic scan (free, no API keys needed)
yelbegen example.com

# Full scan with enhanced UI
yelbegen -f example.com

# API-enhanced scan (requires API keys)
yelbegen -a example.com

# View manual
man yelbegen
```

### API Key Management

```bash
# Add API keys
yelbegen -ua virustotal YOUR_KEY
yelbegen -ua securitytrails YOUR_KEY
yelbegen -ua shodan YOUR_KEY
yelbegen -ua urlscan YOUR_KEY

# Check configured keys
yelbegen -la
```

## Scanners Included

### Free Scanners (No API Required)
- WHOIS information
- DNS records (A, MX, NS, TXT)
- GeoIP location with Google Maps link
- Subdomain enumeration (crt.sh)
- Archive.org Wayback Machine
- HTTP headers and technology detection
- Google Dork suggestions
- AlienVault OTX threat intelligence
- Shodan InternetDB (free tier)

### API Scanners (Requires Keys)
- **VirusTotal**: Domain reputation and security analysis
- **SecurityTrails**: DNS history and comprehensive subdomain discovery
- **Shodan API**: Detailed host intelligence and vulnerability data
- **URLScan.io**: URL analysis and screenshot capture

## Documentation

- Full manual: `man yelbegen`
- API key sources: See `.env.example`
- Installation help: View `reinstall.sh`

## Requirements

- Python 3.9+
- Linux/MacOS
- Optional: API keys for enhanced scanning

## License

GNU General Public License v3.0 - See LICENSE file

## Architecture

Yelbegen uses multiprocessing for efficient parallel scanning:
- **Basic mode**: Python multiprocessing
- **Full/API modes**: ProcessPoolExecutor
- **UI**: Rich library for terminal output

All scanning is passive - no active probes sent to targets.
