https://github.com/akaunting/akaunting

## Title: Authorization bypass in bulk-actions endpoint via unmapped action handle

Affected Versions: confirmed on HEAD commit 084840e (3.1.x line); 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H

CWE: CWE-862 Missing Authorization (also CWE-639 Authorization Bypass Through User-Controlled Key)

### Summary
The generic bulk-actions endpoint decides whether to enforce a permission by looking up a "permission" entry keyed on the user-supplied "handle" parameter. The permission check runs only when that handle has a mapped permission. The UI handles (such as "delete") are mapped, but the underlying method names inherited from the abstract base class ("destroy", "enable", "disable", "duplicate") are not mapped, yet they are still invoked, because the endpoint dispatches the method named by the handle. As a result, an authenticated low-privilege user (for example the default read-only "accountant" role) is correctly blocked when sending handle=delete, but bypasses the check entirely by sending handle=destroy, which performs the same deletion. The same trick applies to enable, disable, and duplicate across essentially every module (transactions, invoices, bills, customers, vendors, items, accounts, categories, and more).

### Details
Route (routes/admin.php:42):
```php
Route::post('bulk-actions/{group}/{type}', 'Common\BulkActions@action')->name('bulk-actions.action');
// effective URI: POST /{company_id}/common/bulk-actions/{group}/{type}
```

The per-action CRUD permission middleware is attached by method name in app/Traits/Permissions.php:496-499:
```php
$this->middleware('permission:create-' . $controller)->only('create', 'store', 'duplicate', 'import');
$this->middleware('permission:read-'   . $controller)->only('index', 'show', 'edit', 'export');
$this->middleware('permission:update-' . $controller)->only('update', 'enable', 'disable');
$this->middleware('permission:delete-' . $controller)->only('destroy');
```
The controller method invoked here is "action", which is in none of these only() lists, so no permission middleware guards BulkActions@action.

The only gate is in-handler, app/Http/Controllers/Common/BulkActions.php:50-64:
```php
$handle = $request->get('handle', '*');                       // attacker-controlled
...
if (
    isset($bulk_actions->actions[$handle]['permission'])      // only fires if a permission is mapped
    && ! user()->can($bulk_actions->actions[$handle]['permission'])
) {
    ... return 403 ...
}
$result = $bulk_actions->{$handle}($request);                 // dynamic dispatch on $handle
```

In app/BulkActions/Banking/Transactions.php the $actions array declares keys "edit" (permission update-banking-transactions), "delete" (permission delete-banking-transactions), and "export" (no permission). There is no "destroy" key.

The abstract base app/Abstracts/BulkAction.php defines both, and "delete" just calls "destroy":
```php
public function delete($request)  { $this->destroy($request); }            // :202
public function destroy($request) {                                        // :214
    $items = $this->getSelectedRecords($request);
    foreach ($items as $item) { $item->delete(); }                         // real deletion
}
```

So handle=delete makes isset($actions['delete']['permission']) true and enforces user()->can('delete-banking-transactions'); handle=destroy makes isset($actions['destroy']['permission']) false, the check is skipped, and destroy() deletes the records. Company scoping stays intact (getSelectedRecords uses the model query with the global Company scope), so this is an in-company privilege escalation, not cross-company. There is no job-layer re-check (app/Jobs/Banking/DeleteTransaction.php authorize() checks only reconciled/transfer state, no permission).

### PoC
Environment: official akaunting/akaunting image with MariaDB, default install (company id 1). Create a user with the seeded "accountant" role (read-only on banking-transactions, holds admin-panel read). Create two income transactions (ids 1 and 2).

Authenticate as the accountant and send both requests to POST /1/common/bulk-actions/banking/transactions with headers X-Requested-With: XMLHttpRequest and X-CSRF-TOKEN set to the session token.

Gated handle, correctly blocked:
```
body: handle=delete&selected[]=1
response: {"success":false,"error":true,"message":"You can not access this page."}
result: transaction 1 not deleted
```

Unmapped handle, authorization bypassed:
```
body: handle=destroy&selected[]=2
response: {"success":true,"error":false,"message":"1 record destroy."}
result: transaction 2 deleted (deleted_at set)
```

Same user, same endpoint, same permissions; only the handle value differs. delete is denied, destroy succeeds. This was reproduced end to end on a live instance with the default accountant role.

### Impact
Authenticated low-privilege users can perform actions they lack permission for, against essentially every module reachable via bulk-actions. A read-only user can delete records (handle=destroy) without delete-*, create records (handle=duplicate) without create-*, and change state (handle=enable / handle=disable) without update-*. Impact is unauthorized data destruction and modification within the user's own company. (Companies and Users are defended separately, since their Delete/Update jobs re-check ownership.)


### Disclosure
 - 3 June 2026 - reported via email
 - 13 June 2026 - followed up via email
 - July - reported via https://github.com/akaunting/akaunting/issues/3370
 - September - issue deleted by maintainer
