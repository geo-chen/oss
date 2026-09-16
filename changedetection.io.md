https://github.com/dgtlmoon/changedetection.io


## Finding 1: Stored HTML/markup injection into HTML notifications via scraped page title (watch_title not in the escape set)

Affected version: commit 6f4cc2d

### Summary

The monitored page's `<title>` is scraped into the `watch_title` notification token, but the notification handler's escape pass (added for GHSA-q8xq-qg4x-wphg) only escapes diff/snapshot keys and omits `watch_title`. The notification body is then rendered with a non-autoescaping Jinja sandbox, so a malicious page title is emitted as raw live markup into HTML notification channels (email, Telegram html mode, Discord embeds). Confirmed against the `process_notification`: an `<img onerror>` page title appeared as raw markup in the HTML notification while the adjacent `{{diff}}` was correctly escaped.

### Details

Source: attacker-controlled monitored page `<title>` (changedetection's whole purpose is monitoring third-party pages the operator does not control). Flow:

1. `changedetectionio/worker.py:610` -> `html_tools.extract_title(...)` scrapes the title into `watch['page_title']` (it `html.unescape()`s it at `html_tools.py:789`, so encoded payloads also decode to live markup).
2. `model/Watch.py:424-426` `watch.label` returns `page_title`.
3. `notification/handler.py:558` sets `notification_parameters['watch_title'] = watch.label`.
4. The GHSA-q8xq-qg4x-wphg escape loop at `notification/handler.py:400-414` only escapes keys starting with `diff` or in `{'raw_diff','current_snapshot','prev_snapshot','triggered_text'}`; `watch_title` is not in that set.
5. Sink: `jinja_render(template_str=n_object['notification_body'], **notification_parameters)` (~419-420). `jinja_render` is `safe_jinja.render` (`jinja2_custom/safe_jinja.py:49`), an `ImmutableSandboxedEnvironment` with no `autoescape`, so `{{watch_title}}` is emitted raw.

`{{watch_title}}` is a first-class documented notification token (`templates/_common_fields.html:36`). The web UI is safe (Flask autoescapes `watch.label`); the gap is exclusively the non-autoescaping notification renderer where the dedicated escape pass forgot this key. `watch_tag` shares the gap (operator-set, lower impact). The boundary crossed is untrusted web content reaching the operator's HTML notification channel. Caveats: requires an HTML-format channel (default global format is `htmlcolor`) and `{{watch_title}}` in the template (a commonly-added documented token; not in the default template).

### PoC

```
# host a page with <title><img src=x onerror=alert(document.domain)></title>; monitor it with an HTML notification
# template containing {{watch_title}} -> the notification email/Discord/Telegram renders the raw markup
```

Validated by calling `changedetectionio.notification.handler.process_notification` with `WatchModel` whose `page_title` was produced by `html_tools.extract_title()`, a `null://` capture sink (the shipped capture-only path at handler.py:476-480), `htmlcolor` format, and template `'Watch "{{watch_title}}" changed:\n{{diff}}'` (no vulnerable logic reimplemented):

```
Scraped page_title (stored in watch): '<img src=x onerror=alert(document.domain)>'
=== WHAT WOULD BE SENT (HTML notification) ===
TITLE: Change on <img src=x onerror=alert(document.domain)>
BODY : Watch "<img src=x onerror=alert(document.domain)>" changed:<br>
<span style="background-color: #fadad7; ...">old</span>...price...
[RESULT] raw <img onerror> markup present in HTML notification: True
```

In the same body, `{{diff}}` was correctly rendered as escaped `<span>` tags (the GHSA-q8xq escape pass ran), while `{{watch_title}}` next to it was raw live markup, exactly the missed key.

### Impact

A monitored attacker page injects HTML/markup into the operator's HTML notifications: phishing links and embeds in email/Discord, Telegram html-mode markup, and client-dependent `onerror` execution in some email clients. The operator did not author the content; it crosses from untrusted web content into their trusted notification channel.

### Remediation

Add `watch_title` (and `watch_tag`) to the escaped-key set at `notification/handler.py:403` for HTML formats, or HTML-escape `watch.label` when building `watch_title` in `create_notification_parameters`. Cleanest fix: have `safe_jinja.render` autoescape for HTML notification formats rather than maintaining a manual per-key allowlist that keeps missing untrusted tokens.


### Disclosure
 - 13 June 2026 - reported via https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-p786-3xq7-m552
 - July - followed up via https://github.com/dgtlmoon/changedetection.io/issues/4266
 - July - maintainer responded "Hello, please dont push me, this software is developed for free" and deleted issue
 - 17 September 2026 - no responses since, disclosed

## Finding 2: SSRF via browser-step "Goto URL" action bypasses the SSRF guard (guard only applied to the main watch URL)

Affected version: commit 6f4cc2d

### Summary

The SSRF guard added after prior advisories only validates the main watch URL (`self.watch.link`). The browser-steps automation feature has a separate `Goto URL` action whose target is passed straight to the headless browser's `page.goto()` with no SSRF/IANA/IP check, and the per-step screenshot/HTML is retrievable, exfiltrating the internal response. In the default no-password configuration with a browser backend (the standard docker-compose deployment), this is an unauthenticated SSRF to internal services and cloud metadata. Confirmed against the shipped step-dispatch path: `page.goto` was called with `169.254.169.254`/`127.0.0.1` targets while the SSRF gate was never invoked.

### Details

Source (untrusted): the `optional_value` of a browser step (`Goto URL`/`Goto site`). The save-time form `SingleBrowserStep.optional_value` (`changedetectionio/forms.py:822`) has only `validators.Optional()` with no URL/SSRF check, and the live interactive endpoint `/browser-steps/browsersteps_update` (`changedetectionio/blueprint/browser_steps/__init__.py:333`, `@login_optionally_required`) passes `request.form['optional_value']` straight through.

Flow: `Fetcher.iterate_browser_steps()` (`changedetectionio/content_fetchers/base.py:165`) -> `steppable_browser_interface.call_action()` -> `action_goto_url()`. Sink: `changedetectionio/browser_steps/browser_steps.py:140` `await self.page.goto(value, timeout=0, wait_until='load')`, with no SSRF/IANA/IP check on this path. The project's gate `validate_iana_url()`/`is_url_private_or_parser_confused` (`changedetectionio/processors/base.py:100`) only ever validates `self.watch.link`, the main watch URL.

The boundary crossed is an unauthenticated network attacker in the default config (changedetection ships with no password, so `@login_optionally_required` is fully open) when a Playwright/Chrome browser backend is configured. Even with a password it is a control bypass: the documented SSRF protection (`ALLOW_IANA_RESTRICTED_ADDRESSES`, the watch-URL guard) is rendered ineffective. The headless browser fetches the internal target and the per-step screenshot/HTML is retrievable via `/browser-steps/browsersteps_image`. This is distinct from the prior SSRF advisories (GHSA-3c45-4pj5-ch7m watch URLs, GHSA-jrxm-qjfh-g54f LLM api_base, GHSA-rph4-96w6-q594 parser-differential), all scoped to the watch URL/LLM base which now have guards.

### PoC

```
# add a watch with a browser step: operation="Goto URL", optional_value="http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# (or via /browser-steps/browsersteps_update). Run the step; retrieve the screenshot/HTML via /browser-steps/browsersteps_image
```

Validated by executing `Fetcher.iterate_browser_steps` -> `steppable_browser_interface.action_goto_url`, stubbing only the Playwright `page` object (all step-dispatch and SSRF-decision logic byte-for-byte the clone), with a tripwire wrapping the `is_url_private_or_parser_confused`:

```
=== page.goto() was called with: ===
    http://169.254.169.254/latest/meta-data/
    http://127.0.0.1:9999/internal-admin
=== SSRF gate (is_url_private_or_parser_confused) was called with: ===
    *** NEVER CALLED ***
RESULT: SSRF gate would BLOCK these URLs -> {'http://169.254.169.254/latest/meta-data/': True, 'http://127.0.0.1:9999/internal-admin': True}
```

A second run confirmed the shipped `action_goto_url` forwards `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to `page.goto`, and the shipped gate blocks all three URLs when applied to the main watch URL, proving the gate works but is never reached on the browser-step path.

### Impact

In the default no-password deployment with a browser backend, an unauthenticated attacker makes the server's headless browser fetch internal-only services and cloud instance-metadata endpoints and reads the response via the per-step screenshot/HTML, enabling internal reconnaissance and cloud-credential theft. With a password, it bypasses the documented SSRF protection.

### Remediation

Apply the same `is_url_private_or_parser_confused()`/`validate_iana_url()` check to every browser-step URL: in `action_goto_url`/`action_goto_site` (`browser_steps.py`) before `page.goto`, and at save-time in `SingleBrowserStep` for `Goto URL`/`Goto site`. Honor `ALLOW_IANA_RESTRICTED_ADDRESSES` consistently. Gate `/browser-steps/browsersteps_update` behind auth rather than `login_optionally_required` when no password is set, or document that browser-steps requires authentication.


### Disclosure
 - 13 June 2026 - reported via https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-x9wx-6c32-9556
 - July - followed up via https://github.com/dgtlmoon/changedetection.io/issues/4266
 - July - maintainer responded "Hello, please dont push me, this software is developed for free" and deleted issue
 - 17 September 2026 - no responses since, disclosed

