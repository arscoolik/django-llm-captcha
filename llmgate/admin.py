from django.contrib import admin

from .models import PasskeyCredential


@admin.register(PasskeyCredential)
class PasskeyCredentialAdmin(admin.ModelAdmin):
    list_display = ("user", "label", "sign_count", "created_at", "last_used_at")
    search_fields = ("user__username", "label")
    readonly_fields = ("credential_id", "public_key", "sign_count", "created_at")
