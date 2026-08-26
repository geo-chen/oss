https://github.com/FrontAccountingERP/FA

## Finding 1: Cross-Site Request Forgery on Financial Transaction Forms in FrontAccounting

**Summary**

While FrontAccounting implements a CSRF token system (the _token hidden field and check_csrf_token() function in includes/ui/ui_controls.inc), this validation is only applied to two pages: admin/users.php and admin/change_current_user_password.php. All financial transaction forms lack this protection entirely.

**Affected pages (confirmed, not exhaustive)**

- gl/gl_journal.php (GL journal entries)
- purchasing/supplier_invoice.php (supplier invoices)
- sales/customer_invoice.php (customer invoices)
- sales/customer_payments.php (customer payments)
- gl/gl_bank.php (bank transactions)
- admin/company_preferences.php (company settings)

**Technical details**

The end_form() function in includes/ui/ui_controls.inc embeds a _token hidden field into forms it generates. However, it does this after the financial transaction forms have already been written -- and those forms do not call check_csrf_token() on submission. The token is generated but never checked.

Verification: retrieving gl/gl_journal.php after authentication confirms no _token field is present in the form. Submitting an arbitrary POST to this endpoint without a _token parameter is processed normally, not rejected.

**Exploit scenario**

An attacker hosts a web page containing a hidden auto-submitting form targeting the victim's FrontAccounting instance. When an authenticated user visits the attacker's page (for example, via a phishing link), the browser automatically sends the session cookie and the forged transaction is recorded. No further interaction is required.

**Proposed fix**

Add check_csrf_token() calls at the start of all transaction-processing code blocks across financial forms, or implement a global CSRF check in includes/session.inc that runs before any POST data is processed. Also consider setting the session cookie SameSite attribute to Strict or Lax to provide defence in depth.

**Environment used for verification**

FrontAccounting 2.4.20, PHP 8.1.34, Apache 2.4.65, MySQL 8.0.

### Disclosure
 - 24 May 2026: reported via email
 - 28 May 2026: accepted the report with thanks. Fix planned in next minor release:

<img width="1110" height="463" alt="image" src="https://github.com/user-attachments/assets/965f0e5c-0a5c-42a8-a10a-d0a5a9769245" />


## Finding 2: Unsalted MD5 Password Hashing in FrontAccounting

**Summary**

FrontAccounting hashes all user passwords using unsalted MD5. This makes stored credentials trivially recoverable if an attacker obtains the database.

**Technical details**

Password hashing is performed in admin/users.php (lines 70 and 76) and admin/change_current_user_password.php (line 72) using PHP's md5() function with no salt:

    md5($_POST['password'])

Authentication in includes/current_user.inc line 79 also uses:

    $Auth_Result = get_user_auth($loginname, md5($password));

MD5 without a salt has three key weaknesses for password storage:

1. No per-password salt means identical passwords have identical hashes, enabling efficient batch cracking and rainbow table lookups.
2. MD5 is extremely fast to compute -- modern GPUs can evaluate tens of billions of hashes per second.
3. Precomputed lookup databases (CrackStation, hashes.com) cover most common passwords and can recover them in milliseconds with no GPU required.

**Verification**

Live instance: the password Admin1234! is stored as 552b2ebe774bb5aaa0ad2021da259d22. This hash is immediately reversed by standard online lookup tools.

**Proposed fix**

Replace md5() with PHP's password_hash(PASSWORD_BCRYPT, ['cost' => 12]) for password storage, and password_verify() for authentication. This change requires a migration path: on successful login, rehash the password with bcrypt if it is currently stored as MD5. This allows a rolling migration without forcing all users to reset passwords immediately.

Also consider increasing the minimum password length from 4 to at least 8 characters, and enforcing complexity requirements.

**Environment used for verification**

FrontAccounting 2.4.20, PHP 8.1.34, MySQL 8.0.

### Disclosure
 - 24 May 2026: reported via email
 - 28 May 2026: accepted reported with thanks. Fix planned in next minor release
