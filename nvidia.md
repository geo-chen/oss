# CVE-2026-65161

https://github.com/NVIDIA/product-security/blob/main/2026/5889/5889.md#acknowledgements

<img width="1715" height="366" alt="image" src="https://github.com/user-attachments/assets/5d7a4607-a66b-4133-8ee1-92fb2175d632" />

## Description

There's a local-file-disclosure issue in AIStore, confirmed on v1.4.8: the
`promote` operation imports a node-local file into a bucket, but the source path
is not restricted, so it reads any absolute path on the target host and exposes it
as a readable object.

The proxy only checks apc.AcePromote (ais/proxy.go), which is part of AccessRW /
the built-in BucketOwnerRole, so a non-admin bucket-scoped user has it. On the
target (ais/tgttxn.go promote begin), only the destination ObjName is checked for
"../"; the source path (c.msg.Name) is passed to os.Stat and promoted with no
directory restriction. The target-side transaction is also reachable
unauthenticated via the missing target-authz + forgeable Ais-Sender-* headers
(separate report).

Validated on a v1.4.8 cluster (AuthN enabled):

  ais object promote /etc/passwd ais://secretbkt/stolen_passwd
  -> promoted "/etc/passwd" => ais://secretbkt
  ais get ais://secretbkt/stolen_passwd -
  -> returned the host's /etc/passwd contents

Pointing it at an SSH key, a Kubernetes service-account token, or a cloud
credential file discloses that file.

Suggested fix: restrict promote source paths to an operator-configured directory
allowlist (resolve symlinks, reject outside paths), require an admin capability
otherwise, and enforce authorization on the target rather than trusting the proxy
and forgeable headers.

https://github.com/NVIDIA/product-security/blob/main/2026/5889/CVE-2026-65161.json
