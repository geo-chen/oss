https://github.com/OWASP/threat-dragon

# OAuth login flow has no state parameter, enabling login CSRF / session swapping

**Status: reported via https://github.com/OWASP/threat-dragon/security/advisories/GHSA-h8xr-g2f8-gxfj on 21 June 2026; rejected by maintainer because finding was discovered by AI agent without human**

### Summary
Threat Dragon's web/server OAuth login flow does not use the OAuth 2.0 `state` parameter. The authorization request the server builds contains no `state`, no `state` is stored for the browser session, and the callback that exchanges the authorization code never validates one. An attacker can obtain an authorization code for their own git provider account and then trick a logged-in or about-to-log-in victim into completing the login with that code. The victim's Threat Dragon session is then bound to the attacker's git account: every threat model the victim opens or saves is read from and written to the attacker's repository, and the victim is shown attacker-controlled content. This is a classic OAuth login CSRF / session-swapping attack and affects all four providers (GitHub, GitLab, Bitbucket, Google).

### Details
The authorization URL is built without a `state` parameter. For GitHub (the others are identical in shape):

td.server/src/providers/github.js, getOauthRedirectUrl (lines 39-42):

    const getOauthRedirectUrl = () => {
        const scope = env.get().config.GITHUB_SCOPE || 'public_repo';
        return `${getGithubUrl()}/login/oauth/authorize?scope=${scope}&client_id=${env.get().config.GITHUB_CLIENT_ID}`;
    };

No `state` is generated, stored, or bound to the user's browser session.

The callback handler exchanges whatever `code` arrives in the query string and immediately issues a session JWT. It reads only `req.query.code`; there is no `state` to read or check:

td.server/src/controllers/auth.js, completeLogin (lines 32-51):

    const completeLogin = (req, res) => {
        const provider = providers.get(req.params.provider);
        return responseWrapper.sendResponseAsync(async () => {
            const { user, opts } = await provider.completeLoginAsync(req.query.code);
            const { accessToken, refreshToken } = await jwtHelper.createAsync(provider.name, opts, user);
            tokenRepo.add(refreshToken);
            return { accessToken, refreshToken };
        }, req, res, logger);
    };

The intermediate redirect likewise reflects the code with no state:

td.server/src/controllers/auth.js, oauthReturn (lines 22-30):

    const oauthReturn = (req, res) => {
        let returnUrl = `/#/oauth-return?code=${req.query.code}`;
        ...
        return res.redirect(returnUrl);
    };

The single-page app then takes the `code` straight from the URL fragment and posts it to the callback, choosing the provider from client-side state:

td.vue/src/views/OauthReturn.vue (mounted):

    const resp = await loginApi.completeLoginAsync(this.provider, this.$route.query.code);
    this.$store.dispatch(AUTH_SET_JWT, resp.data);
    this.$router.push('/dashboard');

td.vue/src/service/api/loginApi.js:

    const completeLoginAsync = (provider, code) => api.getAsync(`/api/oauth/${provider}?code=${code}`);

Because Threat Dragon stores the session as a JWT in the SPA store (see td.vue/src/store/modules/auth.js, AUTH_SET_JWT) rather than in a SameSite cookie, the `code` is taken entirely from the URL the victim loads. Nothing ties that code to the victim's own authorization request. An attacker who has completed the provider consent for their own account holds a valid `code` and can drive the victim's browser to `/#/oauth-return?code=ATTACKER_CODE`. The server exchanges it, gets the attacker's provider access token, and issues a JWT whose embedded `provider.access_token` is the attacker's. The session manager `bearer.config.js` then trusts that token for all subsequent `/api/threatmodel/...` repo reads and writes, which operate against the attacker's git account.

A grep of the entire server (`td.server/src`) and the Vue OAuth flow for `state`, `csrf`, or `nonce` returns no anti-CSRF handling.

### PoC
This was reproduced end to end against a mock provider. The security-relevant code path (the real `getOauthRedirectUrl`, the real `completeLoginAsync` token exchange, the real JWT signing, and the real bearer middleware) is exercised verbatim.

1. Configure the server with any OAuth provider, e.g. in `.env`:

    GITHUB_CLIENT_ID=client_abc123
    GITHUB_CLIENT_SECRET=secret_xyz
    ENCRYPTION_KEYS='[{"isPrimary": true, "id": 0, "value": "11223344556677889900aabbccddeeff"}]'
    ENCRYPTION_JWT_SIGNING_KEY=asdfasdfasdf
    ENCRYPTION_JWT_REFRESH_SIGNING_KEY=fljasdlfkjadf

2. Observe the login URL carries no state (live output from `GET /api/login/github`):

    {"status":200,"data":"https://github.com/login/oauth/authorize?scope=public_repo&client_id=client_abc123"}

   There is no `state=` in the URL, so no anti-CSRF token is ever issued.

3. The attacker performs the consent for their OWN account and captures their authorization code (call it ATTACKER_AUTH_CODE_123). They then send the victim a link to:

    https://<threat-dragon-host>/#/oauth-return?code=ATTACKER_AUTH_CODE_123

   (or auto-navigate the victim there). The SPA posts the code to `GET /api/oauth/github?code=ATTACKER_AUTH_CODE_123`.

4. The server exchanges the attacker's code and issues a session JWT bound to the attacker's git account. Verbatim harness output (real provider functions, mock provider endpoint):

    1) Login redirect URL TD sends the victim to:
        http://.../login/oauth/authorize?scope=public_repo&client_id=client_abc123
        contains state=? NO  <-- no anti-CSRF token issued

    2) completeLoginAsync(attackerCode)  [real token exchange, no state checked]
        provider access_token bound to session: gho_ATTACKER_TOKEN_for_ATTACKER_AUTH_CODE_123
        resolved account: attacker-account

    3) TD issued a valid signed session JWT (HS256):
        accessToken[0..50]: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwcm92aWRlc...

    4) bearer.middleware accepts it: YES
        req.user.username         = attacker-account
        req.provider.access_token = gho_ATTACKER_TOKEN_for_ATTACKER_AUTH_CODE_123

The victim is now logged in as, and bound to, the attacker's git account. Any model the victim creates or saves is written to the attacker's repository (data exfiltration), and any model the victim opens is loaded from the attacker's repository (the attacker controls the content the victim sees and edits).

### Impact
OAuth login CSRF / session swapping (CWE-352, CWE-384). An unauthenticated remote attacker, with one click of victim interaction, forces a Threat Dragon user's session to be bound to the attacker's git provider account. Consequences: threat models the victim authors are silently exfiltrated into the attacker's repository, and the victim works on attacker-supplied model content. This affects any server/hosted Threat Dragon deployment using GitHub, GitLab, Bitbucket, or Google OAuth. Desktop/local single-user mode is not affected.

The fix is to generate a cryptographically random `state` value at login, store it bound to the user's browser session, include it in the authorization URL, and reject the callback if the returned `state` does not match. A PKCE flow would further harden the exchange.
