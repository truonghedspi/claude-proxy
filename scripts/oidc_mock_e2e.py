#!/usr/bin/env python3
"""Self-contained OIDC allow/deny E2E harness.

It models the browser authorization-code flow against a local mock IdP and a
sidecar callback. It is intentionally dependency-free; replace the mock issuer
configuration with Entra discovery for production.
"""
from __future__ import annotations

import base64, hashlib, http.server, json, secrets, threading, time, urllib.parse, urllib.request

ISSUER = "http://127.0.0.1:19000"
SIDECAR = "http://127.0.0.1:17890"
TENANT = "test-tenant"
CLIENT_ID = "claude-proxy-e2e"
CLIENT_SECRET = "e2e-client-secret"
ALLOWED = {"allowed@example.com"}
codes: dict[str, str] = {}
sessions: dict[str, dict[str, str]] = {}

def token(email: str) -> str:
    payload = {"iss": ISSUER, "aud": CLIENT_ID, "tenant_id": TENANT, "email": email, "email_verified": True, "exp": int(time.time()) + 300}
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hashlib.sha256((raw + CLIENT_SECRET).encode()).hexdigest()
    return raw + "." + sig

class Idp(http.server.BaseHTTPRequestHandler):
    def reply(self, status, body, content_type="application/json"):
        data = body.encode(); self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == "/.well-known/openid-configuration":
            return self.reply(200, json.dumps({"issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize", "token_endpoint": ISSUER + "/token", "userinfo_endpoint": ISSUER + "/userinfo"}))
        if u.path == "/authorize":
            email = q.get("login_hint", [""])[0]; code = secrets.token_urlsafe(18); codes[code] = email
            redirect = q["redirect_uri"][0] + "?code=" + urllib.parse.quote(code) + "&state=" + urllib.parse.quote(q.get("state", [""])[0])
            return self.send_response(302) or (self.send_header("Location", redirect), self.end_headers())
        self.reply(404, "not found", "text/plain")
    def do_POST(self):
        if self.path != "/token": return self.reply(404, "not found", "text/plain")
        n = int(self.headers.get("Content-Length", "0")); q = urllib.parse.parse_qs(self.rfile.read(n).decode()); code = q.get("code", [""])[0]; email = codes.pop(code, None)
        if not email: return self.reply(400, json.dumps({"error": "invalid_grant"}))
        return self.reply(200, json.dumps({"access_token": token(email), "id_token": token(email), "token_type": "Bearer", "expires_in": 300}))
    def log_message(self, *_): pass

class Sidecar(http.server.BaseHTTPRequestHandler):
    def reply(self, status, body, content_type="application/json"):
        data = body.encode(); self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == "/login":
            state = secrets.token_urlsafe(18); email = q.get("email", [""])[0]
            params = {"client_id": CLIENT_ID, "response_type": "code", "redirect_uri": SIDECAR + "/auth/callback", "state": state, "login_hint": email}
            self.send_response(302); self.send_header("Location", ISSUER + "/authorize?" + urllib.parse.urlencode(params)); self.end_headers(); return
        if u.path == "/auth/callback":
            code = q.get("code", [""])[0]; data = urllib.parse.urlencode({"code": code, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}).encode(); req = urllib.request.Request(ISSUER + "/token", data=data, method="POST"); result = json.loads(urllib.request.urlopen(req).read()); raw, sig = result["id_token"].rsplit(".", 1); expected = hashlib.sha256((raw + CLIENT_SECRET).encode()).hexdigest(); claims = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
            if sig != expected or claims["iss"] != ISSUER or claims["aud"] != CLIENT_ID or claims["tenant_id"] != TENANT or not claims["email_verified"]: return self.reply(401, json.dumps({"error": "invalid_identity"}))
            if claims["email"] not in ALLOWED: return self.reply(403, json.dumps({"error": "email_not_allowed", "email": claims["email"]}))
            session = secrets.token_urlsafe(24); sessions[session] = claims; return self.reply(200, json.dumps({"ok": True, "email": claims["email"], "session": session}))
        if u.path == "/session": return self.reply(200, json.dumps({"active_sessions": len(sessions), "emails": [v["email"] for v in sessions.values()]}))
        self.reply(404, "not found", "text/plain")
    def log_message(self, *_): pass

def server(cls, port):
    http.server.ThreadingHTTPServer(("127.0.0.1", port), cls).serve_forever()

def get(url):
    try: return urllib.request.urlopen(url).read().decode()
    except urllib.error.HTTPError as e: return f"HTTP {e.code}: {e.read().decode()}"

if __name__ == "__main__":
    threading.Thread(target=server, args=(Idp, 19000), daemon=True).start(); threading.Thread(target=server, args=(Sidecar, 17890), daemon=True).start(); time.sleep(.2)
    allowed = get(SIDECAR + "/login?email=allowed%40example.com"); denied = get(SIDECAR + "/login?email=denied%40example.com")
    print("oidc_discovery=", get(ISSUER + "/.well-known/openid-configuration"))
    print("allowed_flow=", allowed); print("denied_flow=", denied); print("session_state=", get(SIDECAR + "/session"))
    raise SystemExit(0 if '"ok": true' in allowed and "HTTP 403" in denied else 1)
