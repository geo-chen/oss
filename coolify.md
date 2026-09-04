https://github.com/coollabsio/coolify

## Finding: OAuth account takeover via email-only matching (no verified-email/account-link, 2FA bypass)

There's an authentication bypass, confirmed against the OauthController.

`OauthController@callback` (app/Http/Controllers/OauthController.php:27-39) resolves the local account with `User::whereEmail(strtolower(trim($oauthUser->email)))->first()` and calls `Auth::login($user)` directly. There is no provider verified-email check, no oauth_identities/provider binding table (so any matching email logs in), and 2FA (Fortify, config/fortify.php:141) is bypassed because login skips the Fortify pipeline. The callback is unauthenticated (routes/web.php:106).

What I observed: a feature test on the app with a victim (password + verified email + confirmed 2FA) and a mocked gitlab profile `email=victim@corp.com` authenticated as the victim via `/auth/gitlab/callback`; 2FA was never challenged.

POC:
```
attacker -> GET /auth/gitlab/redirect ; complete OAuth on a provider where the attacker controls a
profile whose email = victim@corp.com -> GET /auth/gitlab/callback -> session as victim (no password, no 2FA)
```

Validated by a PHPUnit feature test booting the app (PHP 8.4 + Coolify deps), seeding a victim with a password, verified email, and confirmed 2FA, enabling a `gitlab` `OauthSetting`, mocking Socialite to return an attacker profile with `email=victim@corp.com`, and invoking `OauthController@callback('gitlab')`:

```
[PROOF] /auth/gitlab/callback -> authenticated as user id=1 email=victim@corp.com (victim id=1);
        2fa_confirmed_at was set, never challenged.
OK (1 test, 8 assertions)
```

Impact: attacker presenting a victim's email to a configured provider takes over the account (incl. admin), bypassing password + 2FA. CWE-287, ~8.1 (higher on self-hosted OIDC/GitLab where arbitrary emails are registerable). Net-new: existing advisories only cover OAuth secret leaks; the verified-email/linking gap is an open unmerged feature request, not a published fix.

Suggested fix: require provider verified-email; add an oauth_identities binding table and match on it (explicit confirmed linking); enforce 2FA in the OAuth path. A PoC is available.

## Disclosure
 - reported via email on 13 June 2026
 - followed up via email on 19 July 2026
