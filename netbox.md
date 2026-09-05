https://github.com/netbox-community/netbox

## Finding 1: Cross-user disclosure of private Notifications, Subscriptions, and Bookmarks via REST API and GraphQL (missing per-user scoping)

Package: netbox (netbox/extras/api/views.py, netbox/extras/graphql)

Affected Versions: confirmed on 4.6.2 (commit acef3ac)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5 Medium)

CWE: CWE-639 Authorization Bypass Through User-Controlled Key (with CWE-863)

### Summary

Notifications, Subscriptions, and Bookmarks are per-user private records, and the UI views scope them to the requesting user, but the REST viewsets and GraphQL resolvers expose `Model.objects.all()` with only model-level permission filtering and no `user=request.user` scoping. Any authenticated user holding the relevant view permission (or any authenticated user when `EXEMPT_VIEW_PERMISSIONS=['*']`) reads every user's notifications, subscriptions, and bookmarks, disclosing who is watching/bookmarking which objects and the object names. Confirmed against the real shipped viewsets and GraphQL schema in-process against a real DB.

### Details

Sinks:

- `netbox/extras/api/views.py:163` `NotificationViewSet.queryset = Notification.objects.all()`
- `netbox/extras/api/views.py:174` `SubscriptionViewSet.queryset = Subscription.objects.all()`
- `netbox/extras/api/views.py:152` `BookmarkViewSet.queryset = Bookmark.objects.all()`
- GraphQL: `netbox/extras/graphql/schema.py:42-49` (`notification_list`, `subscription_list`) -> types in `netbox/extras/graphql/types.py:160-196` -> `BaseObjectType.get_queryset` (`netbox/netbox/graphql/types.py:33`).

Notification/Subscription/Bookmark each have a `user` FK and are per-user private (Subscription "maps exactly one user to exactly one object"). The UI views enforce ownership explicitly (`netbox/extras/views.py` uses `request.user.notifications` / `Notification.objects.filter(user=request.user)` / `Subscription.objects.filter(user=request.user)` / `Bookmark.objects.filter(user=request.user)`, ~533-552, 631-723). The REST viewsets and GraphQL resolvers do not: they expose `*.objects.all()` and rely on `RestrictedQuerySet.restrict()` (`netbox/utilities/querysets.py:40`), which filters by the model-level permission `extras.view_notification` etc. with no `user=request.user` scoping. These models are also absent from `EXEMPT_EXCLUDE_MODELS` (`netbox/netbox/settings.py:633`).

The boundary crossed is an authenticated low-privilege user reading other users' private data. Two realistic triggers: (1) an admin or integration grants a user or API token `extras.view_notification`/`view_subscription`/`view_bookmark` for legitimate read-only API access (e.g. a monitoring/audit service account) via NetBox's standard object-permission assignment — no config-file change required, and reachable with `EXEMPT_VIEW_PERMISSIONS` left at its default `[]`; because the permission can't be scoped to "own records only," the grantee receives every user's records instead of just their own (note: the UI's own `NotificationListView`/`SubscriptionListView`/`BookmarkListView` in `netbox/account/views.py` require only `LoginRequiredMixin`, not this permission, so it is never needed just to use the UI — the realistic grant path is API/integration access, not a UI prerequisite); (2) `EXEMPT_VIEW_PERMISSIONS = ['*']` (a documented, commonly-used setting) lets any authenticated user with zero object permissions read everyone's records, confirmed separately. Leaked data: victim username/identity plus `object_repr`/`display` (the name of every object each user subscribed to / was notified about / bookmarked, e.g. confidential site/device/IP/circuit names).

This is the next instance of the authz seam already patched in 4.6.1/4.6.2 (#22198, #22283, #22307); none of those cover these three models.

### PoC

```
GET /api/extras/notifications/    (attacker token, holds view_notification only)  -> all users' notifications
GET /api/extras/subscriptions/                                                     -> all users' subscriptions
GET /api/extras/bookmarks/                                                         -> all users' bookmarks (object names)
# GraphQL: { notification_list { display user { username } } }
```

Validated by booting Postgres 16 + Redis 7, running full 4.6.2 migrations, and executing the actual shipped `NetBoxModelViewSet` subclasses and the actual strawberry `schema` in-process against a real DB. `victim` (pk=1) owns a Notification, Subscription, and Bookmark referencing a private Site `SECRET-PROJECT-SITE`; `attacker` (pk=2) granted only `view_notification`/`view_subscription`/`view_bookmark`:

```
[REST] /api/extras/notifications/ status=200 count=1   notification id=1 user={'username':'victim'}
[REST] /api/extras/subscriptions/ status=200 count=1   subscription id=1 user={'username':'victim'}
[REST] /api/extras/bookmarks/    status=200 count=1    bookmark id=1 user=victim object=SECRET-PROJECT-SITE
[GraphQL] notification_list: [{ "display":"SECRET-PROJECT-SITE", "user":null }]  (object name leaks; nested user null only b/c attacker lacks view_user)
[EXEMPT_VIEW_PERMISSIONS=*] no-perms attacker -> notifications count 1, leaked user=victim
```

### Impact

An authenticated user reads every other user's private notifications, subscriptions, and bookmarks, disclosing identities and the names of objects each user is watching/bookmarking (which can be confidential infrastructure names), across the per-user boundary. Confidentiality-only.

### Remediation

Scope the REST viewsets and GraphQL resolvers to the requesting user, matching the UI: override `get_queryset` on `NotificationViewSet`/`SubscriptionViewSet`/`BookmarkViewSet` to `return super().get_queryset().filter(user=self.request.user)`, and add per-user `get_queryset` filtering to `NotificationType`/`SubscriptionType` (and any Bookmark GraphQL type). Add these three models to `EXEMPT_EXCLUDE_MODELS` so `EXEMPT_VIEW_PERMISSIONS='*'` cannot expose them.

### Disclosure
 - 13 June 2026 - reported via email
 - 13 June 2026 - acknowledged
 - 9 July 2026 - report accepted with clarification questions
 - 10 July 2026 - clarified and adjusted position


## Finding 2: NetBox Data Source backend credentials (git password / S3 secret key) returned in plaintext via REST API and GraphQL to users with only view permission (incomplete fix of #12625)

**Summary**

A NetBox Data Source stores backend credentials in its `parameters` field — for the Git backend an HTTP(S) `password`, and for the Amazon S3 backend the `aws_secret_access_key`. These are explicitly designated `sensitive_parameters` and are censored as `********` in the web UI so that operators viewing a data source never see the stored secret.

However, the REST API (`GET /api/core/data-sources/`) and the GraphQL API (`data_source_list { parameters }`) return the `parameters` object verbatim, including these sensitive values, to **any** authenticated user who holds the `core.view_datasource` object permission. Such a user does not need write (`change_datasource`) permission, staff, or superuser status. This contradicts the UI's deliberate censoring and discloses credentials that authenticate to external systems (the remote Git repository or S3 bucket), enabling lateral movement.

This is an incomplete fix of issue #12625 ("Datasource passwords are displayed in plaintext"). The remediation in PR #13203 only added UI-template masking and changelog masking; the API serialization paths were never updated.

**Details**

The `DataSource.parameters` JSON field holds backend-specific connection settings. Each backend marks which keys are sensitive:

- `netbox/core/data_backends.py:79` — `GitBackend.sensitive_parameters = ['password']`
- `netbox/core/data_backends.py:156` — `S3Backend.sensitive_parameters = ['aws_secret_access_key']`

The base class documents the intent: "An iterable of field names for which the values should not be displayed to the user."

Censoring is applied in exactly two places, both of which miss the API:

1. UI panel — `netbox/templates/core/panels/datasource_backend.html:11-12`:
   ```django
   {% if name in backend.sensitive_parameters %}
     <td>********</td>
   ```
2. Changelog — `netbox/core/models/data.py:164` (`to_objectchange`) replaces sensitive params with `CENSOR_TOKEN`.

The REST serializer exposes `parameters` with no field-level censoring:

`netbox/core/api/serializers_/data.py` (`DataSourceSerializer.Meta.fields`, line 29):
```python
fields = [
    'id', 'url', 'display_url', 'display', 'name', 'type', 'source_url', 'enabled', 'status', 'description',
    'sync_interval', 'parameters', 'ignore_rules', 'owner', 'comments', 'custom_fields', 'created',
    'last_updated', 'last_synced', 'file_count',
]
```

The GraphQL type exposes every model field, including `parameters`:

`netbox/core/graphql/types.py:40-46`:
```python
@strawberry_django.type(
    models.DataSource,
    fields='__all__',
    ...
)
class DataSourceType(PrimaryObjectType):
    ...
```

Both viewsets/types correctly apply the object-permission queryset filter (`restrict(... 'view')`), so the response set is gated by `core.view_datasource` — but once a user is permitted to *view* a data source, the raw secret is serialized to them. The permission boundary that the UI enforces (you may see the object, but not its secret) does not exist in the API.

**PoC**

Prerequisites (admin, one-time): create a Git data source with a password and an S3 data source with a secret key.

```python
# manage.py shell  (admin/setup)
from core.models import DataSource
git = DataSource(name='gitsrc', type='git', source_url='https://example.com/repo.git',
                 parameters={'username':'svc-acct','password':'SUPER-SECRET-GIT-PW','branch':'main'})
git.save()
s3 = DataSource(name='s3src', type='amazon-s3', source_url='https://bucket.s3.amazonaws.com/',
                parameters={'aws_access_key_id':'AKIAEXAMPLE','aws_secret_access_key':'S3-SECRET-KEY'})
s3.save()
```

Attacker is a normal user whose only relevant grant is an ObjectPermission with action `view` on `core | data source` (no change/add/delete, not staff, not superuser). Using that user's API token:

REST:
```bash
curl -s -H "Authorization: Bearer nbt_<key>.<secret>" \
  "https://netbox.example/api/core/data-sources/?type=git"
# ... "parameters": {"branch":"main","password":"SUPER-SECRET-GIT-PW","username":"svc-acct"} ...

curl -s -H "Authorization: Bearer nbt_<key>.<secret>" \
  "https://netbox.example/api/core/data-sources/?type=amazon-s3"
# ... "parameters": {"aws_access_key_id":"AKIAEXAMPLE","aws_secret_access_key":"S3-SECRET-KEY"} ...
```

GraphQL:
```bash
curl -s -H "Authorization: Bearer nbt_<key>.<secret>" -H "Content-Type: application/json" \
  -X POST https://netbox.example/graphql/ \
  -d '{"query":"{ data_source_list { name parameters } }"}'
```

Observed live response (canary values, netbox-docker NetBox 4.6.x):
```json
{"data": {"data_source_list": [
  {"name": "gitsrc", "parameters": {"branch": "main", "password": "SUPER-SECRET-GIT-PW", "username": "svc-acct"}},
  {"name": "s3src",  "parameters": {"aws_access_key_id": "AKIAEXAMPLE", "aws_secret_access_key": "S3-SECRET-KEY"}}
]}}
```

The same user opening `/core/data-sources/1/` in the UI sees the password rendered as `********`. The API discloses what the UI hides.

**Impact**

A low-privileged, authenticated user (only `view` on data sources) can extract the plaintext credentials NetBox uses to reach external systems — a Git repository password/PAT or an AWS S3 secret access key. These credentials typically grant access beyond NetBox itself (read/write to the source repository or bucket), so the disclosure crosses a trust boundary and enables lateral movement and potential supply-chain impact on the synced content. The UI's deliberate `********` masking demonstrates that exposing these values to viewers is contrary to design; the REST and GraphQL APIs defeat that control. This is an incomplete remediation of issue #12625.

Recommended fix: censor `sensitive_parameters` in `DataSourceSerializer` (e.g. replace sensitive keys with `********`/`CENSOR_TOKEN` in `to_representation`, mirroring `to_objectchange`) and exclude or scrub `parameters` on `DataSourceType` in GraphQL, so the API matches the UI's masking for users without an explicit secret-reveal privilege.

### Disclosure
 - 19 June 2026 - reported via email
 - 19 June 2026 - acknowledged
 - 27 June 2026 - report accepted and is under security and engineering team's review
 - 17 August 2026 - followed up on email
 - 5 September 2026 - no response; disclosed
