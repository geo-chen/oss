https://github.com/rubyzip/rubyzip

## Finding: Path traversal in rubyzip Entry#extract via sibling-directory prefix

The extraction guard in Entry#extract uses a string-prefix check without a trailing separator, allowing extraction into a sibling directory outside the destination.
```
lib/zip/entry.rb:289-303
  dest_dir     = ::File.absolute_path(destination_directory || '.')
  extract_path = ::File.absolute_path(::File.join(dest_dir, entry_path))
  unless extract_path.start_with?(dest_dir)   # no trailing File::SEPARATOR
    ... return self
  end
```
With destination `.../upload` and an attacker-controlled entry name `../upload_backup/owned.sh`, extract_path becomes `.../upload_backup/owned.sh`, which start_with?('.../upload') accepts, so the file is written outside `upload/`. Entry names allow `..` (check_name only blocks leading `/` and length), Zip::File#extract delegates here, and the existing name_safe? helper is never called.

Live-validated on rubyzip 3.3.1:
```
  destination = /tmp/rzv/upload
  entry name  = ../upload_backup/owned.sh
  result      => /tmp/rzv/upload_backup/owned.sh written ("PWNED-by-attacker"); /tmp/rzv/upload empty
```
This is an incomplete fix of the 3.0.0 traversal hardening (#540): plain `../parent` is blocked, but the sibling-prefix case is not.

Suggested fix: require an exact match or a trailing separator, e.g.
  unless extract_path == dest_dir || extract_path.start_with?(dest_dir + ::File::SEPARATOR)
and/or actually invoke name_safe? on entry names before extraction.

## Disclosure

 - 4 June 2026 - reported via email
 - 4 June 2026 - report accepted
