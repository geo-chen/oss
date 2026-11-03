https://github.com/pfsense/pfsense


# Stored Cross-Site Scripting (XSS) via Unsanitized Configuration Restore in pfSense

`diag_backup.php`'s restore flow, gated by the assignable 
"WebCfg - Diagnostics: Backup & Restore" privilege 
(not full System Administrator), hands an uploaded XML file 
to `restore_config_section()` (`pfsense-utils.inc:908`), which
parses it with `parse_xml_config()` and writes the result straight into
`$config` via `config_set_path()`, no sanitizer call anywhere in that
chain. A full (no-area) restore goes through `config_install()`
(`config.lib.inc:767`), which only validates XML well-formedness before
replacing `config.xml` outright, same gap. `interfaces` and `sysctl` are
both individually selectable restore areas in `diag_backup.php`'s own
dropdown, so this doesn't require restoring anything else.

Reproduction, from a default install:

1. As a user holding only `page-diagnostics-backup-restore`, build a
   configuration-section XML file:
   ```xml
   <pfsense>
   	<interfaces>
   		<opt1>
   			<if>igb2</if>
   			<descr>&lt;script&gt;alert(document.domain)&lt;/script&gt;</descr>
   			<enable>1</enable>
   		</opt1>
   	</interfaces>
   </pfsense>
   ```
2. On Diagnostics > Backup & Restore, select "Interfaces" as the Backup
   area and restore from that file.
3. As any other user with access to Interfaces > Interface Assignments,
   including full System Administrator, the payload executes in their
   session.


https://github.com/user-attachments/assets/0407ba53-07de-4712-b5c6-ccd025dcb320

The render side (`interfaces_assign.php:503`, `interfaces_bridge.php:121`,
`services_captiveportal_zones.php:94`, `system_advanced_sysctl.php:142`,
`system_crlmanager.php:541`/`:694`) is unchanged from the earlier report;
this is specifically the restore path reaching those sinks without
passing through the save-time checks you pointed to.

I reproduced this against a default install of pfSense
Plus 26.07-RELEASE in an isolated VM: created a user scoped to only the
Backup & Restore privilege, restored the crafted "Interfaces" section as
that user, then logged in separately as System Administrator and
confirmed the payload executed on `interfaces_assign.php`. 

Suggested fix: run the same per-field validation the GUI forms already
use (`remove_bad_chars()`, the CRL character check, `strip_tags()`)
against the parsed configuration inside `restore_config_section()` and
`config_install()`, so a restore can't reintroduce values the forms
themselves would reject.

## Disclosure
 - 30 Oct 2026 - initial report 
 - 3 Nov 2026 - responded by Netgate team as "intended"
   
<img width="1400" height="1807" alt="004_live_vm_user_privileges_confirmed" src="https://github.com/user-attachments/assets/f9395990-a07f-4dc8-bddf-8a4227fa61f8" />

<img width="1400" height="1200" alt="004_live_vm_limited_user_denied" src="https://github.com/user-attachments/assets/e2173360-09ac-4b5e-a786-7404c6b85687" />

<img width="1400" height="1200" alt="004_live_vm_restore_form" src="https://github.com/user-attachments/assets/fc23e591-54fd-4dc9-b380-678ff427fddd" />

<img width="1400" height="1200" alt="004_live_vm_restore_success" src="https://github.com/user-attachments/assets/d8730e06-efc8-4f2e-94c6-b2bcbe22d227" />

<img width="1400" height="1200" alt="004_live_vm_xss_fired" src="https://github.com/user-attachments/assets/a6c90f8b-86a7-4d2e-b23e-bee0efe09d39" />




