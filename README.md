# django-llmgate

Requests that look automated must pass a passkey check. Browsers pass
untouched. One page to enrol a passkey, one middleware, one TTL setting.

## Install

```python
INSTALLED_APPS = [..., "llmgate"]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "llmgate.middleware.LLMGateMiddleware",   # after auth
    ...
]

urlpatterns += [path("llmgate/", include("llmgate.urls"))]

LLMGATE = {
    "RP_ID": "example.com",             # registrable suffix of ORIGIN's host
    "ORIGIN": "https://example.com",
    "SESSION_TTL": 900,                 # how long one check lasts, seconds
    "MODE": "monitor",                  # "enforce" once you've read the logs
}
```

```bash
pip install 'django-llmgate[passkeys]'
python manage.py migrate llmgate
```

## Use

1. A signed-in user visits **`/llmgate/passkeys/`** and adds a passkey. That is
   the whole registration story.
2. From then on, any request that looks automated gets sent to
   `/llmgate/verify/`, taps their passkey, and is cleared for `SESSION_TTL`
   across **every** endpoint.

Nothing to add to your views. Browsers never see any of it.

Registration needs a signed-in user; verification does not. Credentials are
discoverable, so an automated request can be cleared by any enrolled passkey
without signing in first — the claim being made is *a human is present*, not
*this particular person is here*.

Automated clients that cannot render HTML get a 403 instead of a redirect:

```json
{"error": "human_verification_required", "verify_url": "/llmgate/verify/"}
```

## Detection

One function, `llmgate.detect.looks_automated()`, returning `(bool, reason)`:

| Check | Catches |
|---|---|
| Known crawler UA | GPTBot, ClaudeBot, PerplexityBot, CCBot, … |
| HTTP library UA | requests, httpx, curl, Go-http-client, Scrapy, … |
| Empty User-Agent | trivial scripts |
| **No `Sec-Fetch-*`** | **anything spoofing a browser UA** |
| Chromium UA with no `Sec-CH-UA` | the same, more specifically |

The `Sec-Fetch-*` check does the real work: every current browser sends those
headers and almost no HTTP client does, so a scraper wearing a Chrome
User-Agent is still caught.

Run in `MODE: "monitor"` first and watch the `llmgate` logger:

```
llmgate challenging /reports/ (HTTP library UA: curl/)
```

## What this does and does not do

It stops **scripted clients**: an agent fetching over requests/httpx, a
crawler, a script. Against those, a passkey is a hard stop — there is no code
to read, forward, or autofill, and the private key cannot leave the
authenticator.

It does **not** stop an agent driving a real browser on your machine. That
agent is indistinguishable from you, and when the prompt appears you will
approve it — correctly, because you asked for it. What you get is that the
approval is explicit and expires, rather than being harvested once and reused.

Other limits worth knowing:

- **Detection is heuristic**, and wrong in both directions. Your own curl,
  monitoring and CI get challenged too; give them a route around the gate
  (`EXEMPT_PREFIXES`, or an API with its own auth) rather than trying to make
  them pass a humanity check.
- **Verification needs JavaScript and a WebAuthn-capable browser.**
- **The clearance cookie is bound** to `sha256(User-Agent | IP/24)`, so it does
  not transfer between clients. Handing it to a different tool means matching
  the User-Agent too.
- **`/admin/` is exempt by default.** Remove it from `EXEMPT_PREFIXES` if you
  want it gated.

## Settings

| Key | Default | |
|---|---|---|
| `RP_ID` | `None` | required |
| `ORIGIN` | `None` | required |
| `SESSION_TTL` | `900` | seconds a check lasts |
| `MODE` | `"enforce"` | or `"monitor"` |
| `COOKIE_SECURE` | `True` | `False` for plain-HTTP dev |
| `EXEMPT_PREFIXES` | static, media, admin, health, … | never gated |

## Demo

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
cd demo && python manage.py migrate && python manage.py createsuperuser
python manage.py runserver
```

Open **http://localhost:8000** — not `127.0.0.1`, since `RP_ID` is `localhost`
and WebAuthn checks the origin. Sign in, add a passkey at `/llmgate/passkeys/`,
then:

```bash
curl -s localhost:8000/          # 403 human_verification_required
```

No hardware? Chrome DevTools → **⋮ → WebAuthn** → virtual authenticator, with
*user verification* on.

```bash
cd demo && python manage.py test demoapp    # 14 tests
```

The passkey ceremonies run against a software authenticator, so the whole flow
is covered without hardware. The `dev` extra pins `fido2` to 0.9.x because
soft-webauthn 0.1.x imports `fido2.ctap2.AttestedCredentialData`, which moved
in fido2 1.0 and was removed in 2.0.

## Verified

Django 6.1.1, py_webauthn 3.0.1, 14 tests passing: browsers pass untouched;
curl / GPTBot / a spoofed Chrome UA are all challenged; registration then
clearance works across every endpoint; clearance works without signing in;
replayed assertions rejected; clearance does not transfer between clients;
`SESSION_TTL` expiry re-challenges; monitor mode never blocks.

**Not verified in a real browser.** The sandbox this was built in could not
bind a listening socket, so everything went through Django's test client. The
JS is syntax-checked only — `navigator.credentials` and the templates are what
your first `runserver` will actually exercise.
