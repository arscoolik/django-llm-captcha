import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from . import webauthn_flows as flows
from .tokens import mark_verified


def _safe_next(request):
    candidate = request.GET.get("next") or "/"
    if url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return candidate
    return "/"


@login_required
def passkeys(request):
    """The registration endpoint. Sign in, add a passkey, done."""
    return render(request, "llmgate/passkeys.html",
                  {"credentials": request.user.llmgate_passkeys.all()})


@require_POST
@login_required
def register_options(request):
    return JsonResponse({"options": flows.registration_options(request)})


@require_POST
@login_required
def register_verify(request):
    payload = json.loads(request.body or "{}")
    ok = flows.register(request, payload.get("credential"), payload.get("label", ""))
    return JsonResponse({"ok": ok}, status=200 if ok else 400)


def verify(request):
    """The challenge page automated requests are sent to."""
    return render(request, "llmgate/verify.html", {"next": _safe_next(request)})


@require_POST
def verify_options(request):
    return JsonResponse({"options": flows.verification_options(request)})


@require_POST
def verify_submit(request):
    payload = json.loads(request.body or "{}")
    if not flows.verify(request, payload.get("credential")):
        return JsonResponse({"ok": False}, status=400)
    return mark_verified(request, JsonResponse({"ok": True}))
