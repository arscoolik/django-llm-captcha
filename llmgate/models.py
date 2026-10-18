from django.conf import settings
from django.db import models


class PasskeyCredential(models.Model):
    """A WebAuthn credential. The private key lives in the authenticator's
    secure element and cannot be exported -- unlike a TOTP secret, there is
    nothing here an agent can copy, autofill, or be told over chat."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="llmgate_passkeys",
    )
    # base64url text: portably indexable and unique on every backend.
    credential_id = models.CharField(max_length=512, unique=True)
    public_key = models.BinaryField()
    sign_count = models.PositiveBigIntegerField(default=0)
    label = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "passkey credential"

    def __str__(self):
        return self.label or self.credential_id[:16]
