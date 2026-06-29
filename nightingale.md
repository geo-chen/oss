# Any low-privilege ("Standard" role) authenticated user can read all datasource credentials (MySQL/Postgres/ClickHouse passwords, BasicAuth secrets, HTTP bearer tokens) in plaintext

https://github.com/ccfos/nightingale

Affected Versions: confirmed on commit b8329ab 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5 Medium / High depending on credential criticality)

CWE: CWE-862 Missing Authorization (+ CWE-200 Exposure of Sensitive Information)

## Summary
center/router/router.go:501 registers `POST /api/n9e/datasource/list` with `pages.POST("/datasource/list", rt.auth(), rt.user(), rt.datasourceList)` — only generic-user auth, no admin gate. The handler at center/router/router_datasource.go:34-51 calls `models.GetDatasourcesGetsBy(...)` followed by `DB2FE()` and passes the result through `DatasourceCache.DatasourceFilter`. `DatasourceFilter` is the identity function by default (memsto/datasource_cache.go:41) and is not overridden anywhere in the repo. The returned JSON contains `auth.basic_auth_password`, the full `settings` map (which holds `mysql.password`, `postgres.password`, `clickhouse.password`, etc., depending on plugin_type), and `http.headers` (which typically carries bearer tokens). Adjacent endpoints (`/datasource/upsert`, `/datasource/desc`, `/datasource/status/update`, `/datasource` DELETE — router.go:503-506) are correctly gated by `rt.admin()`; only the list endpoint is missed.

## Fix
 - https://github.com/ccfos/nightingale/issues/3173
 - https://github.com/ccfos/nightingale/pull/3175

<img width="844" height="287" alt="image" src="https://github.com/user-attachments/assets/af5eff13-38c3-4bc3-8b80-a87332f2fd1a" />

