"""Is this request coming from a browser a person is sitting at?

Not a solved problem and never will be -- an agent driving a real browser is
indistinguishable from its owner, and it should be, because the owner is
there. What this catches is the scripted client: an HTTP library, a crawler,
an agent fetching over plain requests/httpx.

Cheap, passive, and wrong sometimes in both directions. Run in monitor mode
first and read the logs before you switch it on.
"""
import re

DECLARED_AGENT = re.compile(
    r"(GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-User|Claude-SearchBot|"
    r"anthropic-ai|PerplexityBot|Perplexity-User|Google-Extended|Bytespider|"
    r"CCBot|Amazonbot|Applebot-Extended|meta-externalagent|cohere-ai|Diffbot|"
    r"omgili|ImagesiftBot|YouBot|AI2Bot)",
    re.I,
)

HTTP_LIBRARY = re.compile(
    r"(python-requests|python-urllib|aiohttp|httpx|urllib3|Scrapy|Go-http-client|"
    r"node-fetch|undici|axios|okhttp|libwww-perl|Java/|Apache-HttpClient|curl/|"
    r"Wget/|PostmanRuntime|HTTPie)",
    re.I,
)

CLAIMS_CHROMIUM = re.compile(r"(Chrome|Chromium|Edg)/", re.I)


def looks_automated(request):
    """Return (bool, reason). Reason is for your logs, not the client."""
    ua = request.META.get("HTTP_USER_AGENT", "")

    match = DECLARED_AGENT.search(ua)
    if match:
        return True, f"declared agent UA: {match.group(0)}"

    match = HTTP_LIBRARY.search(ua)
    if match:
        return True, f"HTTP library UA: {match.group(0)}"

    if not ua.strip():
        return True, "no User-Agent"

    # Every current browser sends Sec-Fetch-*; almost no HTTP client does.
    # This is the signal that catches a spoofed User-Agent.
    if "HTTP_SEC_FETCH_MODE" not in request.META:
        return True, "no Sec-Fetch-* headers"

    # Real Chromium always sends the low-entropy client hints alongside.
    if CLAIMS_CHROMIUM.search(ua) and "HTTP_SEC_CH_UA" not in request.META:
        return True, "claims Chromium but sends no Sec-CH-UA"

    return False, ""
