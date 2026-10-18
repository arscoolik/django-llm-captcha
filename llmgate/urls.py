from django.urls import path

from . import views

app_name = "llmgate"

urlpatterns = [
    # Registration: one page the user visits to enrol a passkey.
    path("passkeys/", views.passkeys, name="passkeys"),
    path("passkeys/options/", views.register_options, name="register_options"),
    path("passkeys/verify/", views.register_verify, name="register_verify"),

    # Verification: where automated requests get sent.
    path("verify/", views.verify, name="verify"),
    path("verify/options/", views.verify_options, name="verify_options"),
    path("verify/submit/", views.verify_submit, name="verify_submit"),
]
