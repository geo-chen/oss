# Unauthenticated entry content disclosure via GET /v2/entries/:id/text

https://github.com/feedbin/feedbin

## Details

version: Commit 739884a


The endpoint GET /api/v2/entries/:id/text skips authentication entirely. The relevant code in app/controllers/api/v2/entries_controller.rb contains:
```
  skip_before_action :authorize, only: [:text]

  def text
    entry = Entry.find(params[:id])
    render plain: EntriesHelper.text_format(entry.content), content_type: "text/plain"
  end
```
No alternative authentication check is present. Entry IDs are sequential integers. An unauthenticated attacker can iterate integers from 1 upward and retrieve the plain-text content of every article stored in the database, including private newsletter content, personal page-saves, and articles from any user's private subscriptions.

## Proof of concept
```
  curl -H "Host: api.feedbin.com" https://api.feedbin.com/v2/entries/1/text
  # Returns HTTP 200 with the article text -- no credentials required
```
For comparison, the GET /v2/entries/:id endpoint (the :show action) correctly enforces subscription-based access control and returns HTTP 403 for users not subscribed to the relevant feed.

The fix is to remove :text from the skip_before_action list, or to add an explicit authentication check inside the text action.


## Disclosure
- 28 May 2026 - reported privately via email
- 28 May 2026 - fixed in Commit 04b89b8 https://github.com/feedbin/feedbin/commit/04b89b84189e4727ea19d84ea4a44015859b29cc

  no email response (silent fix)
  
<img width="1258" height="714" alt="image" src="https://github.com/user-attachments/assets/fd6941f8-2d89-4fd4-ba6b-9e322c1a232d" />

<img width="865" height="679" alt="image" src="https://github.com/user-attachments/assets/c18990c6-3acb-4838-aab3-1b75268eeec7" />

