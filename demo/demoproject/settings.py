from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "demo-only-do-not-use-in-production"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "llmgate",
    "demoapp",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    # After auth, so policy can see request.user.
    "llmgate.middleware.LLMGateMiddleware",
]

ROOT_URLCONF = "demoproject.urls"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]

DATABASES = {"default": {
    "ENGINE": "django.db.backends.sqlite3",
    "NAME": BASE_DIR / "demo.sqlite3",
}}

STATIC_URL = "/static/"
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LLMGATE = {
    "RP_ID": "localhost",
    "ORIGIN": "http://localhost:8000",
    "SESSION_TTL": 900,       # how long one passkey check lasts
    "MODE": "enforce",        # "monitor" detects and logs without blocking
    "COOKIE_SECURE": False,   # plain-HTTP local dev
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {"llmgate": {"handlers": ["console"], "level": "INFO"}},
}
