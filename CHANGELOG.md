# Changelog

## 0.1.1

Rewritten around a single job: automated requests need a passkey.

- Removed the score ladder, proof-of-work, and `@require_human`
- Detection is one function, `llmgate.detect.looks_automated()`
- `/llmgate/passkeys/` to enrol, `/llmgate/verify/` to clear
- `SESSION_TTL` controls how long one check lasts
- Credentials are discoverable, so verification needs no prior sign-in

## 0.1.0

Withdrawn. Demanded an `ATTEST` rung it could not issue, so any client it
flagged was locked out permanently with no way to satisfy the challenge.
