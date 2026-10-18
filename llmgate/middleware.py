import logging
from urllib.parse import quote

from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import Resolver404, resolve, reverse

from .conf import conf
from .detect import looks_automated
from .tokens import is_verified

log = logging.getLogger("llmgate")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _exempt(path):
    if any(path.startswith(p) for p in conf("EXEMPT_PREFIXES")):
        return True
    # Never gate our own views, or a challenged client is redirected to the
    # challenge, detected again, and redirected again -- forever.
    try:
        return resolve(path).app_name == "llmgate"
    except Resolver404:
        return False


class LLMGateMiddleware:
    """Automated requests must carry a live passkey check. Everything else
    passes untouched."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if _exempt(request.path):
            return self.get_response(request)

        automated, reason = looks_automated(request)
        request.llmgate_automated = automated
        request.llmgate_reason = reason

        if not automated or is_verified(request):
            return self.get_response(request)

        log.info("llmgate challenging %s (%s)", request.path, reason)
        if conf("MODE") != "enforce":
            return self.get_response(request)

        return self.challenge(request)

    def challenge(self, request):
        target = reverse("llmgate:verify")
        if request.method in SAFE_METHODS and "text/html" in request.headers.get("Accept", ""):
            return redirect(f"{target}?next={quote(request.get_full_path())}")

        # A POST body cannot be replayed through an interstitial, and a client
        # that cannot render HTML cannot complete one either.
        response = JsonResponse(
            {"error": "human_verification_required",
             "detail": "This request looks automated. A passkey check is required.",
             "verify_url": target},
            status=403,
        )
        response["Cache-Control"] = "private, no-store"
        return response
