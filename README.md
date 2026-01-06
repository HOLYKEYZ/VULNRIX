# VULNRIX 🛡️

**All-in-one security platform** For Code vulnerability scanning/ digital footprint analysis.

---

## Features

### 🛡️ Code/File Vulnerability Scanner
- **Multi-mode** – Fast, Hybrid, or Deep AI analysis
- **Repo Scan** – Clone and analyze public Git repositories (limit: 50 files max)
- **Zip Scan** – Upload and scan ZIP archives of source code
- **Detections** – SQLi, XSS, command injection, secrets
- **VirusTotal** – file Malware scanning integration
- **AI Malicious Detection** – Detects Code-generated malware patterns

### 🔍 Digital Footprint Scanner
- **Email** – Breach checking, 
- **Dark Web** mentions , monitoring
- **Phone** – Carrier lookup, validation
- **Domain/IP** – WHOIS, DNS, port scanning
- **Username/name** – Social media and webseach enumeration
- **Quick Lookup** – Scan single items fast

---

## Quick Start

```bash
# Clone and setup
git clone <https://github.com/HOLYKEYZ/VULNRIX.git>
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
# Core (Pick the ones you have)
INTELX_API_KEY=          # Primary OSINT
VIRUS_TOTAL_API_KEY=     # Malware scanning
LEAKINSIGHT_API_KEY=     # Breach checking
GROQ_KEY=                # AI scanning

# Optional
SHODAN_API_KEY=
GOOGLE_API_KEY=
SECURITY_TRAILS_API_KEY=
```

---

## Project Structure

```
VULNRIX/
├── scanner/           # Footprint scanner
├── vuln_scan/         # Code vulnerability scanner
├── accounts/          # Authentication
├── c_fallback_modules/  # C performance fallbacks
└── app/templates/     # UI templates
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

## Author

Joseph Ayanda (HOLYKEYZ)

---

## License

GPLv2
GNU GENERAL PUBLIC LICENSE
                       Version 2 License
