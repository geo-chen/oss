

# --readOnly bypass via the export tool (aggregate $out / $merge write stages)

https://github.com/mongodb-js/mongodb-mcp-server/

Version: 1.12.0

### Disclosure
- 5 June 2026 - reported privately via https://github.com/mongodb-js/mongodb-mcp-server/security/advisories/GHSA-gjgm-8chh-7cwc
- 5 June 2026 - closed without explanation/reason
- 8 July 2026 - disclosed

### Summary
In --readOnly mode the server allows tools in the read / metadata categories and blocks writes. The aggregate read tool correctly rejects pipelines containing the write stages $out and $merge, but the export tool also runs an arbitrary user-supplied aggregation pipeline and does not apply that guard. As a result, in --readOnly mode an attacker can run an aggregate pipeline with $out or $merge through the export tool and write to the database (create or overwrite collections, modify documents). Confirmed on 1.12.0: with the server started --readOnly, a direct aggregate $out was blocked, but the same $out via export created a new collection.

### Details
The read-only gate is a tool-category allowlist (dist/esm/tools/tool.js verifyAllowed allows read/metadata/connect). The aggregate tool guards write stages: dist/esm/tools/mongodb/read/aggregate.js calls assertOnlyUsesPermittedStages, which rejects $out/$merge ("In readOnly mode you can not run pipelines with $out or $merge stages."). The export tool (dist/esm/tools/mongodb/read/export.js) is also classified read, but it executes the supplied pipeline via provider.aggregate(database, collection, pipeline, ...) with no assertOnlyUsesPermittedStages / isWriteStage check. So a write stage in an export pipeline runs.

### PoC
Validated on mongodb-mcp-server 1.12.0 against MongoDB 7, server launched with --readOnly, driven over MCP stdio:
```
control aggregate $out -> "Error running aggregate: In readOnly mode you can not run pipelines with $out or $mer..."   // blocked
export $out result -> "Data for namespace test.users is being exported and will be made available under resource URI ..."   // accepted
collections after: users, pwned_out
pwned_out docs: 2
```
The export tool call:
```json
{ "name": "export", "arguments": {
  "exportTitle": "x", "database": "test", "collection": "users",
  "exportTarget": [{ "name": "aggregate", "arguments": { "pipeline": [{ "$match": {} }, { "$out": "pwned_out" }] } }] } }
```
created the pwned_out collection (2 documents). A $merge stage (whenMatched: "replace") likewise overwrites documents in an existing collection.

### Impact
A deployment that runs the MongoDB MCP server in --readOnly mode (to give an agent read-only database access) can have its database written to: arbitrary collections created or replaced ($out), and existing documents/collections overwritten ($merge). The pipeline is attacker-controllable through the export tool arguments, which are LLM-produced and steerable via prompt injection, so the read-only safety control is defeated and integrity is lost.

### Remediation
Apply the same write-stage guard the aggregate tool uses (assertOnlyUsesPermittedStages / isWriteStage rejecting $out and $merge) to the export tool's pipeline before execution when in --readOnly mode, or run export's aggregation through the same permission-checked path as the aggregate tool.



