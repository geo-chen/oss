https://github.com/phpList/phplist3

## Finding: CSRF enables mass subscriber deletion in phpList

### Summary

There is a Cross-Site Request Forgery (CSRF) vulnerability in phpList 3.6.15 and
earlier that allows an unauthenticated attacker to permanently delete and blacklist an arbitrary
number of subscribers by tricking a logged-in super-administrator into visiting a malicious page.

Affected file: public_html/lists/admin/massremove.php
Affected versions: all versions through 3.6.15
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H (8.1 High)
CWE-352

The massremove.php endpoint processes POST requests to delete and blacklist subscriber addresses
without verifying any CSRF token. phpList's CSRF protection functions (verifyToken() and
verifyCsrfGetToken()) are not called in this file.

An attacker can host the following HTML on any website. When a super-administrator visits it
while logged into phpList, the listed subscribers are silently deleted:

    <form id="f" method="POST" action="http://phplist.target.com/lists/admin/?page=massremove">
      <input type="hidden" name="unsubscribe" value="user1@example.com" />
      <input type="hidden" name="blacklist" value="1" />
    </form>
    <script>document.getElementById('f').submit();</script>

I confirmed this vulnerability by:
1. Creating a subscriber in a fresh phpList 3.6.15 Docker installation.
2. Sending the POST request using the administrator session cookie but without a CSRF token.
3. Observing that the subscriber was deleted from phplist_user_user and added to
   phplist_user_blacklist.

The fix is to call verifyToken() at the beginning of massremove.php, consistent with how the
export.php and other sensitive pages protect their POST handlers.

### Disclosure

 - 28 May 2026 - reported via email on versions <= 3.6.15
 - 30 May 2026 - report accepted, requested to test version 3.6.16
 - 3 June 2026 - retested and confirmed to be vulnerable as well
 - 6 July 2026 - fix to be released within 2 weeks
 - 16 September 2026 - disclosed
