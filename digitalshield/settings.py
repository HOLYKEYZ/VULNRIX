"""
Django settings for digitalshield project.
"""
import environ # Reload Triggered
from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Initialize environ
env = environ.Env(
    DEBUG=(bool, False)
)

# Read .env file
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY', default=os.urandom(24).hex())

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env('DEBUG', default=True)

ALLOWED_HOSTS = [
    'vulnrix.onrender.com',
    'localhost',
    '127.0.0.1',
    os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')
]
# Clean up empty strings if env var is missing
ALLOWED_HOSTS = [host for host in ALLOWED_HOSTS if host]

# CSRF settings (port 5000 is default)
CSRF_TRUSTED_ORIGINS = [
    'http://localhost:5000',
    'http://127.0.0.1:5000',
    'https://vulnrix.onrender.com',
]
if os.environ.get('RENDER_EXTERNAL_HOSTNAME'):
    CSRF_TRUSTED_ORIGINS.append(f"https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME')}")

# Default port for development
DEFAULT_PORT = 5000

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'scanner',
    'accounts',
    'vuln_scan.web_dashboard',
    'vuln_scan.nodes',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

ROOT_URLCONF = 'digitalshield.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'app' / 'templates',
            BASE_DIR / 'vuln_scan' / 'web_dashboard' / 'templates',
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'digitalshield.wsgi.application'

# Database
DATABASE_URL = env('DATABASE_URL', default=None)
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

# Sanitize DATABASE_URL (Fix common copy-paste errors)
if DATABASE_URL:
    DATABASE_URL = DATABASE_URL.strip()
    if DATABASE_URL.startswith("psql "):
        DATABASE_URL = DATABASE_URL.split(" ", 1)[1]
    DATABASE_URL = DATABASE_URL.strip("'").strip('"')

if DATABASE_URL:
    import dj_database_url
    DATABASES = {
        'default': dj_database_url.parse(DATABASE_URL, conn_max_age=600)
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# Custom authentication backend
AUTHENTICATION_BACKENDS = [
    'accounts.backends.EmailOrUsernameBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Login URLs
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/accounts/login/'

# API Keys (from environment)
INTELX_API_KEY = env('INTELX_API_KEY', default=None)
GOOGLE_API_KEY = env('GOOGLE_API_KEY', default=None)
CSE_ID = env('CSE_ID', default=None)
GROK_API_KEY = env('GROK_API_KEY', default=None)

# Pagination
SCANS_PER_PAGE = 10

# File Upload Limit (10MB) to prevent HTML 400 errors on large files
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024

# =============================================================================
# C FALLBACK CONFIGURATION
# =============================================================================
# Controls automatic fallback to C implementations when APIs fail

# =============================================================================
# PRODUCTION SECURITY SETTINGS
# =============================================================================
# These settings are automatically enabled when DEBUG=False
if not DEBUG:
    # HTTPS/SSL Settings - Only enable on Render or if explicitly requested
    if os.environ.get('RENDER') or os.environ.get('ENABLE_SSL'):
        SECURE_SSL_REDIRECT = True
        SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    
    # HSTS Settings (HTTP Strict Transport Security)
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    
    # Cookie Security
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    
    # Content Security
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_BROWSER_XSS_FILTER = True

FALLBACK_CONFIG = {
    # Global settings
    'enabled': True,  # Master switch for fallback system
    'prefer_c_over_api': False,  # Set True to always prefer C (for testing)
    'api_timeout': 10,  # Seconds before considering API failed
    'max_retries': 2,  # API retries before C fallback
    'cache_c_results': True,  # Cache C results like API results
    'log_fallback_usage': True,  # Log when fallback is used
    
    # Health check settings
    'health_check_interval': 300,  # Seconds between health checks (5 min)
    'health_check_on_startup': True,  # Check API health on app start
    
    # Per-API settings
    'apis': {
        'google_search': {
            'enabled': True,
            'fallback_threshold': 0.8,  # Use C if 80% requests fail
            'daily_quota': 100,
            'fallback_when_quota_low': 10,
        },
        'intelx': {
            'enabled': True,
            'fallback_threshold': 0.7,
            'min_credits': 10,  # Switch to C when credits below this
        },
        'breach': {
            'enabled': True,
            'fallback_threshold': 0.9,
            'primary_api': 'leakinsight',
            'fallback_apis': ['leak_lookup', 'intelx'],
        },
        'virustotal': {
            'enabled': True,
            'daily_quota': 500,
            'fallback_when_quota_low': 50,
        },
        'shodan': {
            'enabled': True,
            'rotate_keys': True,  # Use multiple API keys
            'fallback_threshold': 0.8,
        },
        'securitytrails': {
            'enabled': True,
            'daily_quota': 50,
            'fallback_when_quota_low': 5,
        },
        'whoisfreaks': {
            'enabled': True,
            'fallback_threshold': 0.8,
        },
        'pulsedive': {
            'enabled': True,
            'fallback_threshold': 0.8,
        },
    },
    
    # Metrics settings
    'metrics': {
        'enabled': True,
        'retention_days': 30,  # Keep metrics for 30 days
        'export_format': 'json',  # json or csv
    }
}

# Additional API Keys for fallback rotation
SHODAN_API_KEY_2 = env('SHODAN_API_KEY_2', default=None)
LEAKINSIGHT_API_KEY = env('LEAKINSIGHT_API_KEY', default=None)
LEAK_LOOKUP_API_KEY = env('LEAK_LOOKUP_API_KEY', default=None)
VIRUS_TOTAL_API_KEY = env('VIRUS_TOTAL_API_KEY', default=None)
SECURITY_TRAILS_API_KEY = env('SECURITY_TRAILS_API_KEY', default=None)
WHO_IS_FREAKS_API_KEY = env('WHO_IS_FREAKS_API_KEY', default=None)
PULSE_DIVE_API_KEY = env('PULSE_DIVE_API_KEY', default=None)
NUMLOOKUP_API_KEY = env('NUMLOOKUP_API_KEY', default=None)
VERIPHONE_API_KEY = env('VERIPHONE_API_KEY', default=None)

# =============================================================================
# PRODUCTION SECURITY SETTINGS
# =============================================================================
# =============================================================================
# PRODUCTION SECURITY SETTINGS
# =============================================================================
# These settings are automatically enabled when DEBUG=False
if not DEBUG:
    # HTTPS/SSL Settings - Only enable on Render or if explicitly requested
    if os.environ.get('RENDER') or os.environ.get('ENABLE_SSL'):
        SECURE_SSL_REDIRECT = True
        SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    
    # HSTS Settings (HTTP Strict Transport Security)
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    
    # Cookie Security
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    
    # Content Security
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_BROWSER_XSS_FILTER = True
