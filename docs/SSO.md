# SSO and multi-IdP design

The SSO seam is provider-neutral OIDC. Microsoft Entra ID is the first
production adapter; Google Workspace, Okta and other providers use the same
authorization-code/PKCE flow and only change issuer discovery and claims
configuration.

```text
Browser ── OIDC Authorization Code + PKCE ──► SSO sidecar
                                               │
                                               ├─ verify issuer/JWKS/signature
                                               ├─ verify nonce, audience, expiry
                                               ├─ verify email_verified
                                               ├─ check tenant + email/group allowlist
                                               └─ issue short-lived local session
                                                        │
Claude Code ── localhost proxy ─────────────────────────┘
                         │ signed identity / mTLS
                         ▼
                  Managed Proxy ──► Anthropic
```

## Why the sidecar exists

Claude Code's browser SSO and the HTTP proxy's client authentication are
separate. A TLS CONNECT proxy cannot read the OAuth token inside the tunnel.
The local sidecar owns the browser login and then supplies a short-lived,
revocable identity to the managed proxy without TLS MITM.

## Provider configuration

The production configuration is generic OIDC:

```env
OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant-id>/v2.0
OIDC_CLIENT_ID=<application-client-id>
OIDC_CLIENT_SECRET=<secret-from-secret-manager>
OIDC_REDIRECT_URI=http://127.0.0.1:17890/auth/callback
OIDC_ALLOWED_TENANT_ID=<tenant-id>
OIDC_SCOPES=openid profile email
```

Entra registration must allow the exact redirect URI. The sidecar must verify
the issuer, audience, signature, nonce, expiry, tenant claim and
`email_verified` before checking the allowlist. No client-supplied email is
trusted.

## Allow decision

The callback makes the allow decision before issuing a session:

- exact email allowlist;
- verified email domain allowlist;
- optional IdP group/role allowlist;
- tenant restriction;
- optional user disabled/revoked state.

Denied users receive `403`, no refresh token is persisted, and no proxy token
is issued. Audit logs contain the normalized email and reason, never OAuth
tokens or authorization codes.

## E2E strategy

The repository should provide a local mock OIDC provider with the same
discovery, authorization, token and JWKS endpoints as an IdP. The E2E flow is:

1. Start mock OIDC and sidecar.
2. Open `/login` in a browser.
3. Submit an allowed or denied email in the mock login page.
4. Follow the callback and verify the sidecar session result.
5. Start Claude Code through the local proxy identity.
6. Verify the managed proxy accepts the allowed session and rejects the denied
   one.

The mock validates the full browser/session/policy/proxy seam. A real Entra
test additionally validates Azure tenant registration and claims; it requires
an Entra application and secret supplied by the deployment owner.

## Security requirements

- Use Authorization Code + PKCE and a cryptographically random state/nonce.
- Store refresh tokens only in the OS keychain or a secret manager.
- Use short-lived proxy sessions and explicit revocation.
- Bind local listeners to loopback; use Unix-socket/OS ACLs where available.
- Use mTLS or signed tokens from sidecar to managed proxy.
- Never log `code`, `id_token`, `access_token`, `refresh_token` or proxy auth.
