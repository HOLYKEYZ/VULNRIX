# VULNRIX 🛡️

**All-in-one security platform** for Code vulnerability scanning and digital footprint analysis.

---

## Features

### 🛡️ Code/File Vulnerability Scanner
- **Scan Modes:**
  - **Fast** – Regex + Semantic analysis (no AI, instant results)
  - **Hybrid** – Regex + AI Verification (2 AI providers validate findings)
- **Repo Scan** – Clone and analyze public Git repositories (up to 500 files)
- **Zip Scan** – Upload and scan ZIP archives of source code
- **Detections** – SQLi, XSS, command injection, hardcoded secrets, CSRF, and more
- **VirusTotal** – File malware scanning integration
- **AI Verification** – GROQ & Gemini confirm findings and add recommendations

### 🔍 Digital Footprint Scanner
- **Email** – Breach checking, Dark Web monitoring
- **Dark Web** – Mentions for Names, Usernames, Domains, and IPs
- **Phone** – Carrier lookup, validation, global coverage
- **Domain/IP** – WHOIS, DNS, port scanning, CIDR analysis
- **De-fi/Crypto** – Bitcoin Address and IPFS Hash scanning
- **Quick Lookup** – Intelligent detection for all types

---

## Quick Start

```bash
# Clone and setup
git clone https://github.com/HOLYKEYZ/VULNRIX.git
cd VULNRIX

python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

pip install -r requirements.txt
cp .env.example .env  # Add your API keys

python manage.py migrate
python manage.py runserver
```

---

## API Keys Required

```env
# AI Providers (for Hybrid mode - 2 keys recommended)
GROQ_KEY=                # Primary AI (fast)
GROQ2_API_KEY=           # Fallback AI 1
GEMINI_API_KEY=          # Fallback AI 2
GEMINI2_API_KEY=         # Fallback AI 3

# OSINT APIs
INTELX2_API_KEY=         # Primary OSINT (Darkweb, BTC, IPFS)
INTELX_API_KEY=          # Fallback
VIRUS_TOTAL_API_KEY=     # Malware scanning
LEAKINSIGHT_API_KEY=     # Breach checking

# Optional
SHODAN_API_KEY=
GOOGLE_API_KEY=
SECURITY_TRAILS_API_KEY=
```

---

## Project Structure

```
VULNRIX/
├── scanner/             # Footprint scanner
├── vuln_scan/           # Code vulnerability scanner
├── accounts/            # Authentication
├── c_fallback_modules/  # C performance fallbacks
└── app/templates/       # UI templates
```

---

## Deployment

Set these for production:

```bash
DEBUG=False
SECRET_KEY=<long-random-key>
ALLOWED_HOSTS=your-domain.com
```

Then:

```bash
python manage.py collectstatic
gunicorn digitalshield.wsgi:application
```

---

## CLI

Run scans directly from terminal:

```bash
# Install
pip install -r requirements.txt

# Make executable
chmod +x cli/vulnrix.py

# Or run with python
python cli/vulnrix.py --help
```

### Commands

```bash
# OSINT scan
python cli/vulnrix.py osint --email user@example.com
python cli/vulnrix.py osint --username johndoe
python cli/vulnrix.py osint --domain example.com

# Code vulnerability scan
python cli/vulnrix.py code --path ./src --mode deep

# Breach check
python cli/vulnrix.py breach --value user@example.com

# Phone scan
python cli/vulnrix.py phone --number +1234567890

# Domain scan
python cli/vulnrix.py domain --name example.com

# IP scan
python cli/vulnrix.py ip --address 1.2.3.4

# Username scan
python cli/vulnrix.py username --handle johndoe

# Quick scan (auto-detect type)
python cli/vulnrix.py quick --value user@example.com

# Release: update version and push
python cli/vulnrix.py release --version 1.0.0 --message "New features"
```

### Options

| Flag | Description |
|------|-------------|
| `--api-url` | API endpoint (default: http://localhost:8000) |
| `--output, -o` | Output format: text, json, sarif |
| `--fail-on` | Exit with error if findings >= severity (code scan) |
| `--dry-run` | Show release without pushing (release command) |

Set API key: `export VULNRIX_API_KEY=your_key`

---

## Author

**Joseph Ayanda (HOLYKEYZ)**

---

## License

**GPLv2**
GNU GENERAL PUBLIC LICENSE
Version 2 License


NOTE: THIS IS JUST A PROJECT
