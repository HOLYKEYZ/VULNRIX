VULNRIX 🛡️

All-in-one security platform for digital footprint analysis and code vulnerability scanning.

live - https://vulnrix.onrender.com

Quick Start

bashgit clone https://github.com/HOLYKEYZ/VULNRIX.git

python -m venv .venv

.venv\Scripts\activate  # Windows

pip install -r requirements.txt

cp .env.example .env

python manage.py migrate

python manage.py runserver

Core Features

Digital Footprint: Email breach checking, phone validation, domain/IP analysis, username enumeration

Code Scanner: Multi-mode vulnerability detection (SQLi, XSS, command injection), VirusTotal integration, AI malware detection

Environment Setup
envINTELX_API_KEY=
VIRUS_TOTAL_API_KEY=
LEAKINSIGHT_API_KEY=
GROQ_KEY=
Production Config
bash# Render Build

pip install -r requirements.txt && python manage.py collectstatic --noinput && python manage.py migrate

# Render Start
gunicorn digitalshield.wsgi:application
License: GPLv2 - GNU GENERAL PUBLIC LICENSE Version 2
