"""The 'a human was here recently' cookie.

Signed, HttpOnly, and bound to a coarse client fingerprint so it cannot be
lifted and replayed from somewhere else. Not a URL parameter: a token in a
query string leaks into access logs, Referer headers and browser history.
"""
import hashlib
import ipaddress

from django.core import signing

from .conf import conf

SALT = "llmgate.verified.v1"


def _coarse_ip(raw):
    """Widen to /24 or /48 so ordinary NAT and mobile churn do not invalidate
    a check mid-session."""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{raw}/{prefix}", strict=False))


def binding(request):
    parts = [
        request.META.get("HTTP_USER_AGENT", ""),
        _coarse_ip(request.META.get("REMOTE_ADDR", "")),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def is_verified(request):
    raw = request.COOKIES.get(conf("COOKIE_NAME"))
    if not raw:
        return False
    try:
        data = signing.loads(raw, salt=SALT, max_age=conf("SESSION_TTL"))
    except (signing.BadSignature, signing.SignatureExpired, ValueError):
        return False
    return data.get("b") == binding(request)


def mark_verified(request, response):
    response.set_cookie(
        conf("COOKIE_NAME"),
        signing.dumps({"b": binding(request)}, salt=SALT),
        max_age=conf("SESSION_TTL"),
        httponly=True,
        secure=conf("COOKIE_SECURE"),
        samesite="Lax",
        path="/",
    )
    # A CDN caching this would hand one person's clearance to everyone.
    response["Cache-Control"] = "private, no-store"
    return response
