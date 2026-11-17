https://github.com/Stirling-Tools/Stirling-PDF

# Local file read via SVG <image> scheme-less href in the SVG-to-PDF converter (sanitizer blocklist bypass)

Affected version: commit 88adb7a


### Summary

The SVG-to-PDF converter renders attacker-uploaded SVGs with Apache Batik. The SVG sanitizer strips external URL attributes only when they begin with `http://`, `https://`, `//`, or `file:`, so a scheme-less `<image>` href such as `/etc/passwd` or `../../secret.png` is never classified as external, never SSRF-checked, and survives untouched. Batik resolves it against the document base URI `file:///input.svg`, reads the local file, and embeds its pixels in the output PDF. With login disabled by default, this is an unauthenticated local file read of any image-decodable file on the server. Confirmed against real Batik 1.19 and the verbatim sanitizer logic: a PNG stored outside the SVG was read and its bytes embedded in the render.

### Details

Source: the `xlink:href` / `href` / `src` attribute on an SVG `<image>` element in an uploaded `.svg`, via `POST /api/v1/convert/svg/pdf`.

Sink: `app/core/src/main/java/stirling/software/SPDF/utils/SvgToPdf.java:61` builds the document with `factory.createSVGDocument("file:///input.svg", inputStream)` then `builder.build(ctx, svgDoc)` with a default `UserAgentAdapter` and a live `DocumentLoader`, so Batik resolves and loads the `<image>` href as an external resource and embeds the decoded pixels.

Broken control: `app/common/src/main/java/stirling/software/common/util/SvgSanitizer.java`. The sanitizer strips a URL attribute only when `isExternalUrl(value) && !isUrlAllowed(value)` (~line 161). `isExternalUrl` (~line 232) returns true only for values starting with `http://`, `https://`, `//`, or `file:`. A scheme-less path (`/etc/passwd`, `../../etc/passwd`, `/var/lib/secret.png`) is not classified as external, so it is never checked and survives. `<image>` is not in `DANGEROUS_ELEMENTS`, so the element is kept. The explicit `file:///...` and internal-host `http://` vectors are correctly blocked by `SsrfProtectionService` (verified: `file:` -> `URI.getHost()==null` -> blocked); the bypass is specifically the relative/absolute scheme-less path that never reaches the SSRF service.

The boundary crossed is an unauthenticated network attacker (default `enableLogin=false`) supplying an SVG that the server processes, causing it to read its own local filesystem and return the bytes in the response PDF.

### PoC

Upload an SVG containing `<image xlink:href="/etc/passwd" .../>` (or a path to any image file) to `POST /api/v1/convert/svg/pdf`; the rendered PDF embeds the file's decoded contents.

Validated against Batik 1.19 jars and the verbatim sanitizer decision logic:

```
sanitizer decision (copied verbatim from SvgSanitizer.java):
  xlink:href file:///etc/passwd      -> SURVIVES_SANITIZER=false   (correctly blocked)
  xlink:href /etc/passwd             -> SURVIVES_SANITIZER=true    (BYPASS)
  xlink:href ../../../../etc/passwd  -> SURVIVES_SANITIZER=true    (BYPASS)
  href       /etc/shadow             -> SURVIVES_SANITIZER=true    (BYPASS)

Batik render of victim.svg with <image xlink:href="/.../SECRET_outside.png"> (color 0xAB12CD, outside the SVG),
exact same factory call / base URI file:///input.svg / UserAgentAdapter / DYNAMIC context as SvgToPdf.convert:
  GVT built. RasterImageNode bounds = width=10,height=10   (= secret file's real dimensions)
  Pixel at (50,50) = 0xAB12CD (secret file color = 0xAB12CD)
  *** FILE CONTENTS EXFILTRATED: rendered pixel matches secret file ***
```

Batik opened, decoded, and embedded a file outside the SVG; the rendered pixel equals the secret file's bytes-derived color, proving content exfiltration into the output PDF.

### Impact

Any image-decodable file on the server (PNG/JPEG/GIF/TIFF/BMP and any bytes Batik's image readers accept) is exfiltrated into the returned PDF: secrets stored as images, other users' uploaded assets, config/key files in those formats. Unauthenticated by default. This is a local file read, not http SSRF (the `//` and `http://` prefixes are caught), so the scope is the server filesystem.

### Remediation

In `SvgSanitizer`, treat the `<image>` (and `<use>`, `<feImage>`) URL attributes as an allowlist, not a blocklist: permit only `#fragment` and non-script `data:` values and reject everything else, including scheme-less relative/absolute paths. Equivalently, make `isExternalUrl` return true for any value that is not a pure fragment or `data:` URI so it is forced through `isUrlAllowed`. As defense in depth, configure Batik with a restrictive `ExternalResourceSecurity`/`ScriptSecurity` on the `UserAgent` in `SvgToPdf` so external resource loading is denied at the renderer regardless of sanitizer gaps.

## Disclosure
 - 13 June 2026 - reported privately via https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-v97v-3m37-j634
 - 19 July 2026 - followed up via https://github.com/Stirling-Tools/Stirling-PDF/issues/7092
 - 19 July 2026 - maintainer confirmed fix
 - 4 September 2026 - followed up

<img width="898" height="627" alt="image" src="https://github.com/user-attachments/assets/00fdb439-fbc7-44ff-974f-7b7e39ed782f" />
