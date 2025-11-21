import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------
# Security
# ---------------------------
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'fallback-secret')
DEBUG = os.environ.get('DJANGO_DEBUG', '') != 'False'
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost').split(',')

# ---------------------------
# Installed apps
# ---------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "cyberattack",
]

# ---------------------------
# Middleware
# ---------------------------
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "cyberattack.firewall_middleware.FirewallMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "cyberattack.middleware.MaintenanceMiddleware",
]

ROOT_URLCONF = "cybersecurity.urls"

# ---------------------------
# Templates
# ---------------------------
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "cybersecurity.wsgi.application"

# ---------------------------
# Database (PostgreSQL for Render)
# ---------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get('DB_NAME'),
        "USER": os.environ.get('DB_USER'),
        "PASSWORD": os.environ.get('DB_PASSWORD'),
        "HOST": os.environ.get('DB_HOST'),
        "PORT": os.environ.get('DB_PORT', '5432'),
    }
}

# ---------------------------
# Password validators
# ---------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------
# Internationalization
# ---------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Africa/Nairobi"
USE_I18N = True
USE_TZ = True

# ---------------------------
# Static files (with Whitenoise)
# ---------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# ---------------------------
# Default primary key field type
# ---------------------------
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------
# Email Configuration (Render)
# ---------------------------
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = f"Cybersecurity System <{EMAIL_HOST_USER}>"

# ---------------------------
# Logging
# ---------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "file": {"level": "INFO", "class": "logging.FileHandler", "filename": BASE_DIR / "security.log"},
        "console": {"level": "INFO", "class": "logging.StreamHandler"},
    },
    "loggers": {
        "cyberattack.monitoring": {"handlers": ["file", "console"], "level": "INFO", "propagate": True},
    },
}

# ---------------------------
# Security Headers
# ---------------------------
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# ---------------------------
# Session & CSRF Security
# ---------------------------
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# ---------------------------
# Authentication
# ---------------------------
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"
