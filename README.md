VULNRIX 🛡️

All-in-one security platform for digital footprint analysis and code vulnerability scanning.

Live Demo: https://vulnrix.onrender.com

Features
🔍 Digital Footprint Scanner

Email: Breach checking & monitoring

Phone: Carrier lookup, validation

Domain/IP: WHOIS, DNS, port scanning

Username: Social media enumeration

Quick Lookup: Scan single items instantly

🛡️ Code/File Vulnerability Scanner

Multi-mode: Fast, Hybrid, or Deep AI analysis

Detections: SQLi, XSS, command injection, secrets

VirusTotal Integration: Malware scanning

AI Malicious Detection: Detects GPT-generated malware patterns

Quick Start
# Clone repository
git clone https://github.com/HOLYKEYZ/VULNRIX.git
cd VULNRIX

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Add your API keys
cp .env.example .env

# Run migrations
python manage.py migrate

# Start development server
python manage.py runserver

Required API Keys
INTELX_API_KEY=          # Core OSINT scanning
VIRUS_TOTAL_API_KEY=     # Malware scanning
LEAKINSIGHT_API_KEY=     # Breach checking
GROQ_KEY=                # AI scanning

Optional
SHODAN_API_KEY=
GOOGLE_API_KEY=
SECURITY_TRAILS_API_KEY=

Project Structure
VULNRIX/
├── scanner/             # Digital footprint scanner
├── vuln_scan/           # Code vulnerability scanner
├── accounts/            # Authentication
├── c_fallback_modules/  # C performance fallbacks
└── app/templates/       # UI templates

Deployment

Set these for production (Environment Variables):

| Variable | Value |
| :--- | :--- |
| `DEBUG` | `False` |
| `SECRET_KEY` | `<long-random-key>` |
| `ALLOWED_HOSTS` | `vulnrix.onrender.com` |
| `DATABASE_URL` | `postgres://...` (from Supabase/Neon) |
| `PYTHONUNBUFFERED` | `true` |
| `DJANGO_SETTINGS_MODULE` | `digitalshield.settings` |

### Database Setup (Supabase/Neon)
1. Create a free database on [Supabase](https://supabase.com) or [Neon](https://neon.tech).
2. Copy the **Connection String** (Transaction Mode / port 6543 or 5432).
3. Add it as `DATABASE_URL` in Render.

### Render Build Command
```bash
pip install -r requirements.txt && python manage.py collectstatic --noinput && python manage.py migrate
```

### Render Start Command
```bash
gunicorn digitalshield.wsgi:application
```

License

GPLv2 – GNU GENERAL PUBLIC LICENSE Version 2