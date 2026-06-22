# sml-x509

Pure Standard ML **X.509 v3 certificate parser** and **RSA signature
verifier** — decodes DER/PEM certificates (RFC 5280), exposes the common fields
and v3 extensions, and verifies certificate signatures whose issuer key is RSA
(PKCS#1 v1.5 **and** PSS) via the vendored [`sml-rsa`](https://github.com/sjqtentacles/sml-rsa).
Green under both **MLton** and **Poly/ML**, with no FFI, no threads, and no
wall-clock reads — validity is checked against a time you pass in, so everything
is deterministic and byte-identical across compilers.

It is the PKI capstone of the sjqtentacles ecosystem, sitting on top of
`sml-rsa`, `sml-asn1`, and `sml-pem`.

## Features

- **Parsing** of X.509 v3 certificates from **DER** (`parse`) and **PEM**
  (`parsePem`, every `CERTIFICATE` block): tbsCertificate, version, serial
  number, signature algorithm, issuer / subject distinguished names, validity
  (UTCTime *and* GeneralizedTime), subjectPublicKeyInfo, and the common v3
  extensions — **basicConstraints, keyUsage, extKeyUsage, subjectAltName,
  authority/subjectKeyIdentifier**.
- **RSA signature verification** — `verifySignature {cert, issuer}` checks the
  certificate's signature against the issuer's RSA public key. Both
  **RSASSA-PKCS1-v1_5** and **RSASSA-PSS** are supported; the hash and (for PSS)
  the salt length are read from the certificate's signatureAlgorithm.
  `verifySelfSigned` is the self-signed special case.
- **Path / chain validation** — `verifyChain {cert, intermediates, roots, time}`
  walks leaf → intermediates → a trusted self-signed root, checking
  issuer/subject linkage, the validity window against the injected `time`, the
  CA flag in basicConstraints, and the RSA signature on every link.
- **Exact signed bytes** — signatures cover the *verbatim* DER of the
  tbsCertificate, which a decode/re-encode round trip may not reproduce. The
  parser captures the original byte-slice, so verification is exact.

## Scope & roadmap

Signature **verification** is implemented for **RSA issuer keys only**. EC
(ECDSA) and Ed25519 certificates still **parse** — their public keys and
signature algorithms are recognised (`publicKeyAlg`, `signatureAlg`) — but
verifying them returns `Unsupported`:

> NIST **P-256 / P-384** curve arithmetic does not yet exist in the ecosystem (a
> future `sml-p256`), and secp256k1 is not the curve real-world certificates
> use. ECDSA/Ed25519 **certificate verification is therefore deferred**; this is
> a roadmap item, not a parsing limitation.

Full name-constraint processing and policy validation are also out of scope for
this version.

## Byte & integer conventions

Every encoded value — the certificate, the tbsCertificate, the
subjectPublicKeyInfo, signature bytes, key identifiers — is a raw `string`: one
byte per `char`, codepoints `0..255`. The serial number is carried by the
vendored `BigInt.int`; `serialHex` renders it as lowercase hex. Times are parsed
into a comparable `{year,month,day,hour,minute,second}` record (UTC), with
`compareTime` for ordering against your own "now".

## API

```sml
type cert
val parse    : string -> cert        (* DER *)
val parsePem : string -> cert list   (* all CERTIFICATE blocks *)

val subject       : cert -> name        val issuer    : cert -> name
val commonName    : name -> string option
val serialHex     : cert -> string      val version   : cert -> int
val validity      : cert -> validity    (* { notBefore, notAfter } *)
val signatureAlg  : cert -> sigAlg      val publicKeyAlg : cert -> keyAlg
val dnsNames      : cert -> string list (* subjectAltName dNSName *)
val basicConstraints : cert -> basicConstraints option   (* { ca, pathLen } *)
val isCA / keyUsage / extKeyUsage / subjectKeyId / authorityKeyId : ...

val tbsCertificateDer       : cert -> string   (* the exact signed bytes *)
val subjectPublicKeyInfoDer : cert -> string
val rsaPublicKey            : cert -> Rsa.pubkey option

datatype verifyResult = Verified | Failed | Unsupported of string
val verifySignature : { cert : cert, issuer : cert } -> verifyResult
val verifySelfSigned : cert -> verifyResult

datatype chainResult = ChainOk | ChainError of string
val verifyChain : { cert : cert, intermediates : cert list
                  , roots : cert list, time : time } -> chainResult
```

See [`src/x509.sig`](src/x509.sig) for the full signature and documentation.

## Example

```sml
val leaf  = hd (X509.parsePem leafPem)
val inter = hd (X509.parsePem intermediatePem)
val ok    = X509.verifySignature { cert = leaf, issuer = inter }  (* Verified *)
```

`make example` runs [`examples/demo.sml`](examples/demo.sml), which parses the
committed RSA fixture chain, prints the leaf's fields, and verifies every link:

```
sml-x509 demo
=============

Leaf certificate
  subject     : test.sjqtentacles.example
  issuer      : sjqtentacles Test Intermediate CA
  serial      : 1337b3ac7ef2e8094d8ec39bc0da3bd42774f645
  version     : v3
  not before  : 2026-06-22T00:45:17Z
  not after   : 2028-09-24T00:45:17Z
  sig alg     : sha256WithRSAEncryption
  is CA       : false
  key usage   : digitalSignature, keyEncipherment
  ext key use : serverAuth, clientAuth
  SAN dnsNames: test.sjqtentacles.example, www.sjqtentacles.example

Signature verification (RSA, against the real issuer keys)
  leaf  <- intermediate : Verified
  inter <- root         : Verified
  root  (self-signed)   : Verified
  ISRG Root X1 (self)   : Verified

Path validation (leaf -> intermediate -> trusted root)
  at 2027-01-01T00:00:00Z : ChainOk
  at 3000-01-01T00:00:00Z : ChainError: certificate outside its validity window
```

## Test fixtures

Real certificates, committed under [`test/fixtures/`](test/fixtures/):

- An OpenSSL-generated **RSA-2048 chain** — `root.crt` (self-signed CA),
  `intermediate.crt` (CA, `pathlen:0`), `leaf.crt` (end-entity with SAN dnsNames,
  PKCS#1 v1.5) and `leafpss.crt` (end-entity signed with **RSASSA-PSS**,
  sha256/mgf1-sha256, salt 32).
- A self-signed **P-256** cert (`ec.crt`) — parses; ECDSA verification returns
  `Unsupported`.
- The real, well-known **ISRG Root X1** (`isrgrootx1.pem`, RSA-4096, the
  Let's Encrypt root) — exercises parsing of a production certificate and
  self-signed signature verification.

The suite asserts correct field extraction (subject/issuer CN, serial, validity
dates, SAN, basicConstraints, keyUsage/extKeyUsage), that RSA signatures
**verify TRUE against the real issuer keys** (PKCS#1 v1.5 and PSS), that a
tampered tbsCertificate and a tampered signature both verify **FALSE**, that an
expired certificate is rejected given an injected "now" past `notAfter`, and
that a full chain validates — **53 checks, identical under MLton and Poly/ML**.

## Build

```sh
make test        # build + run the suite under MLton
make test-poly   # run the suite under Poly/ML
make all-tests   # both
make example     # build + run the demo
```

Requires `mlton` and/or `poly` on `PATH`.

## Layout & vendoring

Layout B: the library lives in `src/`; its dependencies are vendored verbatim
(byte-identical to their `origin/main`, verified with `diff -rq`) under
`lib/github.com/sjqtentacles/`:

- `sml-bigint` — arbitrary-precision integers (the serial number, RSA modpow).
- `sml-codec` — SHA-1/256/512 and Base64.
- `sml-asn1` — the common-subset DER codec.
- `sml-pem` — PEM framing (unwraps `CERTIFICATE` blocks).
- `sml-rsa` — RSA signature verification (PKCS#1 v1.5 / PSS).

The dependency graph is a set of diamonds — `sml-x509` reaches `BigInt` and the
SHA codec through several paths. Everything is pulled in along a **single** path:
[`src/x509.mlb`](src/x509.mlb) includes only `sml-rsa`, whose `sources.mlb`
brings `sml-asn1` (→ `BigInt`) and `sml-pem` (→ the codec) each exactly once, so
no structure is defined twice. The Poly/ML use-chain in the
[`Makefile`](Makefile) mirrors that order.

### Why a hand-rolled DER reader?

The parser is a small offset-aware DER reader rather than the vendored `Asn1`
decoder, for two reasons: (1) it returns the **verbatim byte-slice** of every
element, so the signed `tbsCertificate` bytes are exact; and (2) real
certificates use ASN.1 types outside the common subset (UTCTime/GeneralizedTime,
IA5String) and IMPLICIT primitive context tags (SAN `dNSName [2]`,
authorityKeyIdentifier `keyIdentifier [0]`) that the strict common-subset
decoder rejects by design. The vendored `Asn1`, `Pem`, `BigInt`, and `Rsa` are
still used for PEM framing, the serial number, and signature verification.

## Determinism

No FFI, threads, wall-clock or OS randomness. Validity checking takes the
current time as an explicit argument, so every operation is reproducible and
byte-identical across MLton and Poly/ML.

## License

MIT — see [`LICENSE`](LICENSE).
