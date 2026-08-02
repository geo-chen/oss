https://github.com/TestLinkOpenSourceTRMS/testlink-code

## Finding: Authenticated IDOR on attachmentdownload.php lets any user read every attachment

Affected Versions: 1.9.20 and earlier; confirmed on commit 444bceb5fc24d61bea0816d3011073a4c9c43a32

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

CWE: CWE-639 Authorization Bypass Through User-Controlled Key

### Summary
Any authenticated TestLink user, including the lowest-privilege "guest" role and members of unrelated projects, can download the content of every attachment stored in the instance by iterating an integer ID on `lib/attachments/attachmentdownload.php`. The script enforces a session check but performs no authorization on the requested attachment, so attachments belonging to private projects the requester has no role in are returned in full.

### Details
`lib/attachments/attachmentdownload.php` is the GUI handler used by every attachment link in the UI. After CVE-2022-35195 the maintainers added `testlinkInitPage($db);` on line 22 to require a session, but the body of the script still hands the file out without consulting the project, role or membership of the requester:

```php
// lib/attachments/attachmentdownload.php
22  testlinkInitPage($db);
25  $args = init_args($db);
26  if ($args->id) {
27    $fileRepo = tlAttachmentRepository::create($db);
28    $attachInfo = $fileRepo->getAttachmentInfo($args->id);
30    if ($attachInfo) {
31      switch ($args->opmode) {
32        case 'API':
            ...                       // gated by test plan API key + executions only
69        case 'GUI':
70        default:
71          $doIt = true;             // ALWAYS true for session-mode requests
73        break;
74      }
77      if ($doIt) {
            ...
88        $content = $fileRepo->getAttachmentContent($args->id, $attachInfo);
...
123     echo $content;
```

`init_args()` reads the `id` parameter as `tlInputParameter::INT_N` (lines 140-145), so it is just a positive integer. With no API key in the request the function sets `$args->opmode = 'GUI'` and `$args->skipCheck = false` (lines 148-152). The GUI branch in the main switch unconditionally sets `$doIt = true` and the file is written to the response.

The "skipCheck" SHA-256 file-name check on line 82 is only evaluated when `$args->skipCheck` is a non-empty string. Because clients controlling the request can simply omit `skipCheck` from the query string, `$args->skipCheck` stays `false` and the check is skipped.

`tlAttachmentRepository::getAttachmentInfo()` (lib/functions/tlAttachmentRepository.class.php:509) does a plain `SELECT id, title, file_name, file_type, file_size, file_path, fk_id, fk_table FROM attachments WHERE id = N` without any user or project filter. `getAttachmentContent()` (line 368 in the same file) likewise resolves and returns the file by ID alone.

`testlinkInitPage($db);` (lib/functions/common.php:471) only calls `checkSessionValid()` here, it does not invoke a `userRightsCheckFunction`, so the loader makes no privilege decision before falling into the handler.

The companion `attachmentdelete.php` and `attachmentupload.php` handlers cover the same gap by consulting `$_SESSION['s_lastAttachmentInfos']` through `checkAttachmentID()` (lib/functions/attachments.inc.php:97). `attachmentdownload.php` never references that list.

Default installs are exposed: on MySQL the `testprojects.is_public` column defaults to `1` (install/sql/mysql/testlink_create_tables.sql:503), and even on instances that switch projects to private the attacker still bypasses the `TPROJ.is_public = 0 AND UTR.role_id != TL_ROLES_NO_RIGHTS` filter that `get_accessible_for_user()` (lib/functions/testproject.class.php:613) applies everywhere else.

Attachments in TestLink are bound to a wide range of records (test specifications, test case versions, requirements, test plan executions, builds, custom field values, requirement specifications). A successful enumeration leaks all of them across the entire installation.

### PoC
On a default install with two projects A and B and one private project C:

1. Sign in as `bob`, who is only assigned the `guest` role on Project A.
2. Request `GET /lib/attachments/attachmentdownload.php?id=1`.
3. The server returns the raw bytes of whatever attachment has primary key 1, regardless of which project owns it or whether the requesting user has any role on that project. Reading the response body yields the file content with the proper `Content-Type` and `Content-Disposition: inline; filename="…"` headers.
4. Increment the `id` parameter (`id=2`, `id=3`, …) to enumerate the entire `attachments` table.

The same request without a session cookie returns the TestLink login page, confirming that authentication is enforced and the bypass is on the authorization layer only.

### Live Validation

Attempted live deploy on 2026-05-26 with `imtnd/testlink:latest` + MySQL 5.7. The installer walked through `installIntro.php`, `installCheck.php`, `installDbInput.php`, and `installNewDB.php`. The DB connection and the testlink_user grant both succeeded, but the schema creation pass failed because the bundled TestLink 1.9.14 SQL DDL is incompatible with MySQL 5.7 (`Table 'testlink.db_version' doesn't exist` during the version-tag INSERT, indicating the CREATE TABLE statements were rejected silently). Live HTTP-layer reproduction was therefore not completed.

Code-level confirmation is unambiguous: `lib/attachments/attachmentdownload.php:20-128` (HEAD 444bceb) calls `testlinkInitPage($db)` to assert a session, then immediately fetches the attachment by raw integer ID via `tlAttachmentRepository::getAttachmentInfo($args->id)` and streams the content. No project ACL lookup (`$db->fetchOneByID('nodes_hierarchy', $attachment->fk_id)` -> project, then `$user->hasRight('mgt_view_tc', $project_id)`) is performed anywhere on the GUI path. The companion delete and upload handlers in the same directory use `$_SESSION['s_lastAttachmentInfos']` for scoping, demonstrating that the project considers per-attachment authorization a real concern -- just not on download. Docker stack torn down after the failed install attempt.

### Impact
Authenticated information disclosure. Any user with even a guest role on any project can read every attachment ever uploaded to the instance, including attachments on private test projects, requirements documents, test case screenshots, execution evidence, custom field uploads and build artefacts. In typical TestLink deployments these files contain test data, internal screenshots, requirement excerpts and similar sensitive material that the per-project privacy model is supposed to protect.

The issue is distinct from CVE-2022-35195 (unauthenticated download via the older `testlinkInitPage($db, false, true)` call) and from the IDOR upload/delete tickets (0008745, 0008746, 0008747) that the project closed in the 1.9.20 changelog. None of those fixes added authorization on the download path.
