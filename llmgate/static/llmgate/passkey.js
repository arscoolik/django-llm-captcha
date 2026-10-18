/* Both WebAuthn ceremonies. The page says which one via data-mode. */
(function () {
  const root = document.getElementById("llmgate");
  if (!root) return;
  const cfg = root.dataset;
  const status = document.getElementById("llmgate-status");
  const button = document.getElementById("llmgate-go");

  const toBuf = (s) => {
    const p = s.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(p + "=".repeat((4 - (p.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  };
  const toB64u = (b) =>
    btoa(String.fromCharCode(...new Uint8Array(b)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const post = (url, body) =>
    fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": cfg.csrf },
      credentials: "same-origin",
      body: JSON.stringify(body || {}),
    });

  if (!window.PublicKeyCredential) {
    status.textContent = "This browser does not support passkeys.";
    button.disabled = true;
    return;
  }

  button.addEventListener("click", async () => {
    button.disabled = true;
    status.textContent = "Waiting for your device…";
    const creating = cfg.mode === "register";

    try {
      const { options } = await (await post(cfg.optionsUrl)).json();
      const parsed = JSON.parse(options);

      let publicKey;
      const parser = creating
        ? PublicKeyCredential.parseCreationOptionsFromJSON
        : PublicKeyCredential.parseRequestOptionsFromJSON;
      if (parser) {
        publicKey = parser.call(PublicKeyCredential, parsed);
      } else {
        publicKey = { ...parsed, challenge: toBuf(parsed.challenge) };
        if (creating) {
          publicKey.user = { ...parsed.user, id: toBuf(parsed.user.id) };
          publicKey.excludeCredentials = (parsed.excludeCredentials || [])
            .map((c) => ({ ...c, id: toBuf(c.id) }));
        } else {
          publicKey.allowCredentials = (parsed.allowCredentials || [])
            .map((c) => ({ ...c, id: toBuf(c.id) }));
        }
      }

      const cred = creating
        ? await navigator.credentials.create({ publicKey })
        : await navigator.credentials.get({ publicKey });

      let credential;
      if (cred.toJSON) {
        credential = cred.toJSON();
      } else {
        const r = cred.response;
        credential = {
          id: cred.id, rawId: toB64u(cred.rawId), type: cred.type,
          clientExtensionResults: {},
          response: creating
            ? { clientDataJSON: toB64u(r.clientDataJSON),
                attestationObject: toB64u(r.attestationObject) }
            : { clientDataJSON: toB64u(r.clientDataJSON),
                authenticatorData: toB64u(r.authenticatorData),
                signature: toB64u(r.signature),
                userHandle: r.userHandle ? toB64u(r.userHandle) : null },
        };
      }

      const body = creating
        ? { credential, label: navigator.platform || "passkey" }
        : { credential };
      const result = await post(cfg.submitUrl, body);

      if (!result.ok) {
        status.textContent = "That did not verify. Try again.";
        button.disabled = false;
        return;
      }
      status.textContent = "Done.";
      window.location.replace(creating ? window.location.pathname : cfg.next);
    } catch (err) {
      status.textContent = err.name === "NotAllowedError"
        ? "Cancelled or timed out. Try again."
        : "Something went wrong: " + err.message;
      button.disabled = false;
    }
  });
})();
