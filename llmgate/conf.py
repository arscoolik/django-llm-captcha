from django.conf import settings
from django.core.signals import setting_changed
from django.dispatch import receiver

DEFAULTS = {
    # WebAuthn. RP_ID must be a registrable suffix of ORIGIN's host.
    "RP_ID": None,              # "example.com"
    "ORIGIN": None,             # "https://example.com"
    "RP_NAME": "llmgate",

    # How long one passkey check lasts before the next agent request is
    # challenged again.
    "SESSION_TTL": 900,

    # "monitor" detects and logs but lets everything through.
    "MODE": "enforce",

    "COOKIE_NAME": "llmgate",
    "COOKIE_SECURE": True,      # False only for plain-HTTP local dev

    "EXEMPT_PREFIXES": [
        "/static/", "/media/", "/favicon.ico", "/robots.txt",
        "/.well-known/", "/health", "/admin/",
    ],
}

_cache = {}


def conf(name):
    if name not in _cache:
        _cache[name] = getattr(settings, "LLMGATE", {}).get(name, DEFAULTS[name])
    return _cache[name]


@receiver(setting_changed)
def _reset(sender, setting, **kwargs):
    if setting == "LLMGATE":
        _cache.clear()
