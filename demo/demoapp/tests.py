"""Browsers pass; automated clients need a live passkey check."""
import base64
import json
from base64 import urlsafe_b64encode
from hashlib import sha256
from struct import pack

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from fido2 import cbor
from soft_webauthn import SoftWebauthnDevice

CHROME = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.9",
    "Sec-Fetch-Mode": "navigate",
    "Sec-CH-UA": '"Chromium";v="140", "Not=A?Brand";v="24"',
}
CURL = {"User-Agent": "curl/8.7.1", "Accept": "*/*"}
GPTBOT = {"User-Agent": "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
          "Accept": "*/*"}
SPOOFED = {"User-Agent": CHROME["User-Agent"], "Accept": "text/html"}
BASE_SETTINGS = {"RP_ID": "localhost", "ORIGIN": "http://localhost:8000",
                 "COOKIE_SECURE": False, "MODE": "enforce"}


class DetectionTests(TestCase):
    def test_browser_passes_untouched(self):
        self.assertEqual(self.client.get("/", headers=CHROME).status_code, 200)
        self.assertEqual(self.client.get("/reports/", headers=CHROME).status_code, 200)

    def test_http_library_is_challenged(self):
        response = self.client.get("/", headers=CURL)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "human_verification_required")
        self.assertEqual(response.json()["verify_url"], "/llmgate/verify/")

    def test_declared_crawler_is_challenged(self):
        self.assertEqual(self.client.get("/", headers=GPTBOT).status_code, 403)

    def test_spoofed_browser_ua_is_still_caught(self):
        """The UA says Chrome; the missing Sec-Fetch-* headers say otherwise."""
        response = self.client.get("/", headers=SPOOFED)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/llmgate/verify/", response["Location"])

    def test_html_capable_client_gets_the_page_not_json(self):
        response = self.client.get("/", headers={**CURL, "Accept": "text/html"})
        self.assertEqual(response.status_code, 302)

    def test_unsafe_method_gets_json(self):
        self.assertEqual(self.client.post("/", headers=CHROME).status_code, 200)
        self.assertEqual(self.client.post("/", headers=CURL).status_code, 403)

    def test_verify_page_does_not_gate_itself(self):
        response = self.client.get("/llmgate/verify/", headers={**CURL, "Accept": "text/html"})
        self.assertEqual(response.status_code, 200)

    @override_settings(LLMGATE={**BASE_SETTINGS, "MODE": "monitor"})
    def test_monitor_mode_never_blocks(self):
        self.assertEqual(self.client.get("/", headers=GPTBOT).status_code, 200)


class UVSoftDevice(SoftWebauthnDevice):
    """soft-webauthn hardcodes flags without the user-verified bit, so it can
    never satisfy userVerification=required. Set UV on both ceremonies."""

    def create(self, options, origin):
        result = super().create(options, origin)
        attestation = cbor.decode(result["response"]["attestationObject"])
        auth_data = bytearray(attestation["authData"])
        auth_data[32] |= 0x04  # safe to patch: fmt='none' signs nothing
        attestation["authData"] = bytes(auth_data)
        result["response"]["attestationObject"] = cbor.encode(attestation)
        return result

    def get(self, options, origin):
        # authData is signed here, so UV must be set before signing.
        self.sign_count += 1
        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": urlsafe_b64encode(
                options["publicKey"]["challenge"]).decode().rstrip("="),
            "origin": origin,
        }).encode()
        auth_data = (sha256(self.rp_id.encode()).digest() + b"\x05"
                     + pack(">I", self.sign_count))
        signature = self.private_key.sign(
            auth_data + sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": urlsafe_b64encode(self.credential_id),
                "rawId": self.credential_id, "type": "public-key",
                "response": {"authenticatorData": auth_data,
                             "clientDataJSON": client_data,
                             "signature": signature,
                             "userHandle": self.user_handle}}


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def as_browser_json(result):
    response = {k: b64u(v) for k, v in result["response"].items() if v is not None}
    return {"id": b64u(result["rawId"]), "rawId": b64u(result["rawId"]),
            "type": result["type"], "response": response, "clientExtensionResults": {}}


def to_raw_options(payload, creating):
    options = json.loads(payload)
    pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    options["challenge"] = pad(options["challenge"])
    if creating:
        options["user"]["id"] = pad(options["user"]["id"])
    return {"publicKey": options}


class PasskeyTests(TestCase):
    ORIGIN = "http://localhost:8000"

    def setUp(self):
        self.user = User.objects.create_user("ada", password="correct-horse")
        self.device = UVSoftDevice()

    def _register(self, client):
        client.force_login(self.user)
        options = client.post("/llmgate/passkeys/options/", headers=CHROME).json()["options"]
        attestation = self.device.create(to_raw_options(options, True), self.ORIGIN)
        return client.post("/llmgate/passkeys/verify/",
                           data=json.dumps({"credential": as_browser_json(attestation),
                                            "label": "test key"}),
                           content_type="application/json", headers=CHROME)

    def _verify(self, client, headers):
        options = client.post("/llmgate/verify/options/", headers=headers).json()["options"]
        assertion = self.device.get(to_raw_options(options, False), self.ORIGIN)
        return client.post("/llmgate/verify/submit/",
                           data=json.dumps({"credential": as_browser_json(assertion)}),
                           content_type="application/json", headers=headers)

    def test_registration_requires_login(self):
        self.assertEqual(
            Client().post("/llmgate/passkeys/options/", headers=CHROME).status_code, 302)

    def test_register_then_automated_request_can_clear(self):
        self.assertEqual(self._register(self.client).status_code, 200)
        self.assertEqual(self.user.llmgate_passkeys.count(), 1)

        agent = Client()
        self.assertEqual(agent.get("/", headers=CURL).status_code, 403)
        self.assertEqual(self._verify(agent, CURL).status_code, 200)
        # Cleared -- and it holds for every endpoint, not just the one hit.
        self.assertEqual(agent.get("/", headers=CURL).status_code, 200)
        self.assertEqual(agent.get("/reports/", headers=CURL).status_code, 200)

    def test_verification_works_without_signing_in(self):
        """Discoverable credentials mean the agent need not authenticate as
        anyone -- the claim is 'a human is present', not 'ada is here'."""
        self._register(Client())
        agent = Client()
        self.assertEqual(self._verify(agent, CURL).status_code, 200)
        self.assertEqual(agent.get("/", headers=CURL).status_code, 200)

    def test_replayed_assertion_is_rejected(self):
        self._register(self.client)
        agent = Client()
        options = agent.post("/llmgate/verify/options/", headers=CURL).json()["options"]
        assertion = self.device.get(to_raw_options(options, False), self.ORIGIN)
        payload = json.dumps({"credential": as_browser_json(assertion)})
        first = agent.post("/llmgate/verify/submit/", data=payload,
                           content_type="application/json", headers=CURL)
        self.assertEqual(first.status_code, 200)
        replay = agent.post("/llmgate/verify/submit/", data=payload,
                            content_type="application/json", headers=CURL)
        self.assertEqual(replay.status_code, 400)

    def test_clearance_does_not_transfer_to_another_client(self):
        self._register(self.client)
        agent = Client()
        self._verify(agent, CURL)
        thief = Client()
        thief.cookies["llmgate"] = agent.cookies["llmgate"].value
        self.assertEqual(
            thief.get("/", headers={**CURL, "User-Agent": "python-requests/2.32"}).status_code,
            403)

    @override_settings(LLMGATE={**BASE_SETTINGS, "SESSION_TTL": -1})
    def test_session_expires(self):
        self._register(self.client)
        agent = Client()
        self._verify(agent, CURL)
        self.assertEqual(agent.get("/", headers=CURL).status_code, 403)
