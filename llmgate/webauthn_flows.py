"""The two WebAuthn ceremonies, with userVerification required throughout.

Registration creates a *discoverable* credential, so the verification step
does not need to know who you are first. Any enrolled passkey can clear a
request -- the claim being made is "a human is present", not "this specific
person is signed in".

Requires: pip install 'django-llmgate[passkeys]'
"""
import base64

from django.utils import timezone

from .conf import conf
from .models import PasskeyCredential

SESSION_KEY = "llmgate_challenge"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _rp_id():
    value = conf("RP_ID")
    if not value:
        raise RuntimeError("settings.LLMGATE['RP_ID'] is not set")
    return value


def _origin():
    value = conf("ORIGIN")
    if not value:
        raise RuntimeError("settings.LLMGATE['ORIGIN'] is not set")
    return value


def registration_options(request):
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    user = request.user
    options = generate_registration_options(
        rp_id=_rp_id(),
        rp_name=conf("RP_NAME"),
        user_id=str(user.pk).encode(),
        user_name=user.get_username(),
        user_display_name=user.get_full_name() or user.get_username(),
        authenticator_selection=AuthenticatorSelectionCriteria(
            # Discoverable, so verification works without signing in first.
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=unb64u(c.credential_id))
            for c in user.llmgate_passkeys.all()
        ],
    )
    request.session[SESSION_KEY] = b64u(options.challenge)
    return options_to_json(options)


def register(request, credential, label=""):
    from webauthn import verify_registration_response

    expected = request.session.pop(SESSION_KEY, None)
    if not expected:
        return False
    try:
        result = verify_registration_response(
            credential=credential,
            expected_challenge=unb64u(expected),
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
            require_user_verification=True,
        )
    except Exception:
        return False

    PasskeyCredential.objects.update_or_create(
        credential_id=b64u(result.credential_id),
        defaults={
            "user": request.user,
            "public_key": result.credential_public_key,
            "sign_count": result.sign_count,
            "label": (label or "passkey")[:100],
        },
    )
    return True


def verification_options(request):
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import UserVerificationRequirement

    options = generate_authentication_options(
        rp_id=_rp_id(),
        # Empty: the authenticator offers whichever discoverable credential
        # it holds for this site, so an anonymous request can still clear.
        allow_credentials=[],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    request.session[SESSION_KEY] = b64u(options.challenge)
    return options_to_json(options)


def verify(request, credential):
    from webauthn import verify_authentication_response

    expected = request.session.pop(SESSION_KEY, None)
    if not expected or not credential:
        return False

    raw_id = credential.get("rawId") or credential.get("id")
    try:
        stored = PasskeyCredential.objects.get(credential_id=raw_id)
    except PasskeyCredential.DoesNotExist:
        return False

    try:
        result = verify_authentication_response(
            credential=credential,
            expected_challenge=unb64u(expected),
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
            credential_public_key=bytes(stored.public_key),
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
    except Exception:
        return False

    # A counter that fails to advance can mean a cloned authenticator, but
    # platform passkeys legitimately report 0 forever -- only enforce
    # monotonicity once a counter is actually in use.
    if stored.sign_count and result.new_sign_count <= stored.sign_count:
        return False

    stored.sign_count = result.new_sign_count
    stored.last_used_at = timezone.now()
    stored.save(update_fields=["sign_count", "last_used_at"])
    return True
