# Coding Task 2 - Patch Notes

## Overview

This patch updates `SampleNetworkClient.py` and `SampleNetworkServer.py` to address the three vulnerabilities identified in Lab 2:

1. Hardcoded password
2. Token list with the potential to continuously grow
3. Plaintext authentication token and authentication

The patch changes both the client and server because the vulnerabilities were part of the overall authentication and session-management design, not isolated to one line or one file.

---

## 1. Password is Hardcoded

### Original issue

The original client sent a password that was directly embedded in the source code. The original server also compared incoming authentication attempts against the same hardcoded password. This violated confidentiality and secret-management requirements because anyone who could read the code could recover the password.

### Patch

Both files now read the shared authentication secret from the `THERMOMETER_PASSWORD` environment variable.

- `SampleNetworkServer.py` requires `THERMOMETER_PASSWORD` to be set before the server starts.
- `SampleNetworkClient.py` first checks `THERMOMETER_PASSWORD`. If it is not set, the client securely prompts the user at runtime with `getpass.getpass()`.

### Security improvement

The password is no longer stored in the source code. This makes the secret easier to rotate and prevents accidental disclosure through source-code access, version control, or code review.

### How to test

Before running the server and client, set the same environment variable in both terminals:

```bash
export THERMOMETER_PASSWORD='ChooseAStrongLabPassword'
```

Then run the server and client normally.

---

## 2. Token List Has the Potential to Continuously Grow

### Original issue

The original server stored authentication tokens in a list. Every successful authentication appended a new token. Tokens were only removed if the client sent `LOGOUT`. If clients authenticated repeatedly without logging out, the list could grow indefinitely and eventually degrade or crash the server.

### Patch

The server no longer uses an unbounded token list. It now uses bounded session management:

- `self.sessions` stores active sessions.
- `MAX_SESSIONS = 32` enforces a hard limit on active sessions.
- `SESSION_TTL_SECONDS = 300` expires sessions automatically.
- `cleanupExpiredAuthState()` removes expired sessions.
- If the session limit is reached, the server denies new sessions with `Too Many Sessions`.

The server also bounds pending authentication challenges:

- `self.challenges` stores temporary login challenges.
- `MAX_CHALLENGES = 64` prevents challenge growth.
- `CHALLENGE_TTL_SECONDS = 30` expires unused challenges.

### Security improvement

The server now enforces limits on authentication state. Repeated authentication attempts can no longer cause unbounded memory growth because old sessions expire and the total number of active sessions is capped.

### How to test

Repeatedly authenticate without logging out. The server should either reuse normal operation while old sessions expire or deny additional sessions once `MAX_SESSIONS` is reached. The session list should not grow without limit.

---

## 3. Plaintext Authentication Token and Authentication

### Original issue

The original client sent the password in plaintext using an `AUTH` command. After authentication, the server returned a bearer token, and the client sent that token in plaintext with later commands. Anyone able to observe the traffic could capture the password or token and replay it.

### Patch

The authentication protocol was changed to use HMAC challenge-response authentication and HMAC-signed commands.

Authentication now works as follows:

1. The client sends `AUTH_CHALLENGE` with a random client nonce.
2. The server returns a random server nonce.
3. The client computes an HMAC proof using the shared secret and both nonces.
4. The server verifies the HMAC proof without receiving the password.
5. The client and server derive a per-session command-signing key.

Protected commands now use this format:

```text
SECURE <session_id> <counter> <hmac>;<command>
```

The session ID is only an identifier. It is not accepted by itself as proof of authentication. The server only processes a command if the HMAC is valid and the counter is strictly increasing.

### Security improvement

The password is never sent over the socket. A reusable bearer token is also no longer sent as the only proof of authentication. Capturing a command does not allow an attacker to replay it because the server enforces increasing counters. Capturing the session ID does not grant access because the attacker would still need the derived session key to generate a valid HMAC.

### How to test

Run the server and client with the same `THERMOMETER_PASSWORD`. The client should still retrieve temperatures. If a command is resent with the same counter, the server should reject it with `Replay Detected`. If the HMAC is changed, the server should reject it with `Bad MAC`.

---

## Files Changed

### `SampleNetworkServer.py`

- Removed the hardcoded password comparison.
- Added environment-variable secret loading.
- Replaced the unbounded `tokens` list with bounded `sessions` and `challenges` dictionaries.
- Added session expiration and cleanup.
- Added a maximum active-session limit.
- Added challenge-response authentication.
- Added HMAC validation for protected commands.
- Added counter-based replay protection.
- Changed `LOGOUT` to a protected command.

### `SampleNetworkClient.py`

- Removed the hardcoded password from authentication calls.
- Added environment-variable and runtime password loading.
- Replaced plaintext `AUTH <password>` with challenge-response authentication.
- Replaced plaintext bearer-token commands with HMAC-signed command packets.
- Added per-session counters to prevent replay.
- Added automatic re-authentication if the server session expires.

---

## Notes

This patch keeps the original UDP-based structure so the lab can still be run with the existing simulator. In a production system, the stronger solution would be to use a secure transport layer such as TLS or DTLS in addition to strong session management. However, within the existing lab architecture, this patch removes plaintext password transmission, removes plaintext bearer-token authentication, and prevents the authentication state from growing without bounds.
