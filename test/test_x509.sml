(* test_x509.sml -- X.509 certificate parsing and verification suite.

   Anchored on real certificates committed under test/fixtures/:
     - an OpenSSL-generated RSA-2048 chain (root -> intermediate -> leaf), with a
       PKCS#1 v1.5 leaf and a separate RSASSA-PSS leaf;
     - a self-signed P-256 cert (parses; ECDSA verification is out of scope);
     - the production ISRG Root X1 (RSA-4096, self-signed).

   The suite checks field extraction (subject/issuer CN, serial, validity, SAN,
   basicConstraints, keyUsage/extKeyUsage), RSA signature verification against
   the real issuer keys (PKCS#1 v1.5 and PSS), rejection of tampered tbs and
   tampered signatures, rejection of an expired cert via an injected "now", and
   full chain path validation. *)

structure X509Tests =
struct
  open Harness
  open Fixtures

  fun one pem = case X509.parsePem pem of
                  (c :: _) => c
                | [] => raise Fail "no certificate in PEM"

  val root  = one rootPem
  val inter = one intermediatePem
  val leaf  = one leafPem
  val pss   = one leafPssPem
  val ec    = one ecPem
  val isrg  = one isrgRootX1Pem

  fun cnOf c = case X509.commonName (X509.subject c) of SOME s => s | NONE => "<none>"
  fun icnOf c = case X509.commonName (X509.issuer c) of SOME s => s | NONE => "<none>"

  (* flip the last byte of a string (corrupts the trailing signature byte) *)
  fun flipLast s =
    let val n = String.size s
        val b = Char.ord (String.sub (s, n - 1))
    in String.substring (s, 0, n - 1) ^ String.str (Char.chr (b mod 255 + 1)) end

  (* flip the first byte of the first occurrence of [pat] in [s] *)
  fun flipAt (s, pat) =
    let
      val n = String.size s and m = String.size pat
      fun find i =
        if i + m > n then raise Fail ("pattern not found: " ^ pat)
        else if String.substring (s, i, m) = pat then i
        else find (i + 1)
      val i = find 0
      val b = Char.ord (String.sub (s, i))
    in String.substring (s, 0, i) ^ String.str (Char.chr (b mod 255 + 1))
       ^ String.extract (s, i + 1, NONE) end

  fun derOf pem = #der (hd (Pem.decode pem))

  fun suiteParseFields () =
    ( section "field parsing (RSA chain)"
    ; checkString "root subject CN"       ("sjqtentacles Test Root CA", cnOf root)
    ; checkString "root issuer CN (self)" ("sjqtentacles Test Root CA", icnOf root)
    ; checkString "intermediate subject CN" ("sjqtentacles Test Intermediate CA", cnOf inter)
    ; checkString "intermediate issuer CN"   ("sjqtentacles Test Root CA", icnOf inter)
    ; checkString "leaf subject CN"  ("test.sjqtentacles.example", cnOf leaf)
    ; checkString "leaf issuer CN"   ("sjqtentacles Test Intermediate CA", icnOf leaf)
    ; checkInt    "leaf is X.509 v3" (2, X509.version leaf)
    ; checkString "leaf serial (hex)" ("1337b3ac7ef2e8094d8ec39bc0da3bd42774f645", X509.serialHex leaf)
    ; checkString "intermediate serial (hex)" ("57fda5642ba98c206a5f1d2eb8e38ec13c3a9eb9", X509.serialHex inter)
    ; checkString "root serial (hex)" ("3aba8eecb687779a8542ca14f486a013ac77709d", X509.serialHex root) )

  fun suiteValidity () =
    let val v = X509.validity leaf
    in
      section "validity dates";
      checkString "leaf notBefore" ("2026-06-22T00:45:17Z", X509.timeToString (#notBefore v));
      checkString "leaf notAfter"  ("2028-09-24T00:45:17Z", X509.timeToString (#notAfter v));
      checkString "ISRG notBefore" ("2015-06-04T11:04:38Z", X509.timeToString (X509.notBefore isrg));
      checkString "ISRG notAfter"  ("2035-06-04T11:04:38Z", X509.timeToString (X509.notAfter isrg))
    end

  fun suiteExtensions () =
    ( section "v3 extensions"
    ; checkBool "leaf is not a CA"       (false, X509.isCA leaf)
    ; checkBool "intermediate is a CA"   (true,  X509.isCA inter)
    ; checkBool "root is a CA"           (true,  X509.isCA root)
    ; (case X509.basicConstraints inter of
         SOME {ca, pathLen} =>
           ( checkBool "intermediate BC ca" (true, ca)
           ; checkBool "intermediate BC pathLen=0" (true, pathLen = SOME 0) )
       | NONE => check "intermediate has basicConstraints" false)
    ; checkStringList "leaf SAN dnsNames"
        (["test.sjqtentacles.example", "www.sjqtentacles.example"], X509.dnsNames leaf)
    ; check "leaf keyUsage has digitalSignature"
        (List.exists (fn s => s = "digitalSignature") (X509.keyUsage leaf))
    ; check "leaf keyUsage has keyEncipherment"
        (List.exists (fn s => s = "keyEncipherment") (X509.keyUsage leaf))
    ; checkStringList "leaf extKeyUsage" (["serverAuth", "clientAuth"], X509.extKeyUsage leaf)
    ; check "leaf has subjectKeyId"   (Option.isSome (X509.subjectKeyId leaf))
    ; check "leaf has authorityKeyId" (Option.isSome (X509.authorityKeyId leaf)) )

  fun suiteAlgAndKey () =
    ( section "algorithms & public keys"
    ; check "leaf sigAlg is sha256WithRSA" (X509.signatureAlg leaf = X509.Sha256WithRsa)
    ; check "pss sigAlg is RSASSA-PSS/sha256/salt32"
        (X509.signatureAlg pss = X509.RsaPss { hash = Rsa.SHA256, saltLen = 32 })
    ; check "leaf publicKeyAlg is RSA" (X509.publicKeyAlg leaf = X509.RsaKey)
    ; check "leaf has an RSA public key" (Option.isSome (X509.rsaPublicKey leaf))
    ; check "ISRG publicKeyAlg is RSA"  (X509.publicKeyAlg isrg = X509.RsaKey)
    ; check "EC cert publicKeyAlg is EC"
        (case X509.publicKeyAlg ec of X509.EcKey _ => true | _ => false)
    ; check "EC cert sigAlg is ecdsa-with-SHA256" (X509.signatureAlg ec = X509.EcdsaWithSha256)
    ; check "EC cert has no RSA public key" (not (Option.isSome (X509.rsaPublicKey ec))) )

  fun suiteVerify () =
    ( section "RSA signature verification (real issuer keys)"
    ; check "leaf verifies against intermediate"
        (X509.verifySignature { cert = leaf, issuer = inter } = X509.Verified)
    ; check "intermediate verifies against root"
        (X509.verifySignature { cert = inter, issuer = root } = X509.Verified)
    ; check "root self-signed verifies"
        (X509.verifySelfSigned root = X509.Verified)
    ; check "ISRG Root X1 self-signed verifies (real RSA-4096)"
        (X509.verifySelfSigned isrg = X509.Verified)
    ; check "PSS leaf verifies against intermediate"
        (X509.verifySignature { cert = pss, issuer = inter } = X509.Verified)
    ; check "leaf does NOT verify against the wrong issuer (root)"
        (X509.verifySignature { cert = leaf, issuer = root } = X509.Failed)
    ; check "EC self-signed verification is unsupported"
        (case X509.verifySelfSigned ec of X509.Unsupported _ => true | _ => false) )

  fun suiteTamper () =
    let
      val tamperedSig = X509.parse (flipLast (derOf leafPem))
      val tamperedTbs = X509.parse (flipAt (derOf leafPem, "test.sjqtentacles.example"))
    in
      section "tamper rejection";
      check "tampered signature is rejected"
        (X509.verifySignature { cert = tamperedSig, issuer = inter } = X509.Failed);
      check "tampered tbsCertificate is rejected"
        (X509.verifySignature { cert = tamperedTbs, issuer = inter } = X509.Failed);
      (* the tbs tamper actually changed the subject CN that was parsed *)
      check "tampered tbs really changed the parsed subject"
        (cnOf tamperedTbs <> "test.sjqtentacles.example")
    end

  (* injected "current time" instants *)
  val tValid   = { year = 2027, month = 1,  day = 1, hour = 0, minute = 0, second = 0 }
  val tExpired = { year = 3000, month = 1,  day = 1, hour = 0, minute = 0, second = 0 }
  val tTooEarly= { year = 2000, month = 1,  day = 1, hour = 0, minute = 0, second = 0 }

  fun suiteChain () =
    ( section "path / chain validation"
    ; check "full chain validates at a valid time"
        (X509.verifyChain { cert = leaf, intermediates = [inter]
                          , roots = [root], time = tValid } = X509.ChainOk)
    ; check "PSS leaf chain validates"
        (X509.verifyChain { cert = pss, intermediates = [inter]
                          , roots = [root], time = tValid } = X509.ChainOk)
    ; check "expired leaf (now past notAfter) is rejected"
        (case X509.verifyChain { cert = leaf, intermediates = [inter]
                               , roots = [root], time = tExpired } of
           X509.ChainError _ => true | _ => false)
    ; check "not-yet-valid leaf (now before notBefore) is rejected"
        (case X509.verifyChain { cert = leaf, intermediates = [inter]
                               , roots = [root], time = tTooEarly } of
           X509.ChainError _ => true | _ => false)
    ; check "chain without a trusted root is rejected"
        (case X509.verifyChain { cert = leaf, intermediates = [inter]
                               , roots = [], time = tValid } of
           X509.ChainError _ => true | _ => false)
    ; check "chain missing its intermediate is rejected"
        (case X509.verifyChain { cert = leaf, intermediates = []
                               , roots = [root], time = tValid } of
           X509.ChainError _ => true | _ => false)
    ; check "self-signed root validates as its own chain"
        (X509.verifyChain { cert = root, intermediates = []
                          , roots = [root], time = tValid } = X509.ChainOk) )

  fun suiteTimeCompare () =
    ( section "time comparison"
    ; check "notBefore < notAfter" (X509.compareTime (X509.notBefore leaf, X509.notAfter leaf) = LESS)
    ; check "now after notAfter detected"
        (X509.compareTime (tExpired, X509.notAfter leaf) = GREATER) )

  fun suitePemMulti () =
    let val all = X509.parsePem (rootPem ^ intermediatePem ^ leafPem)
    in
      section "PEM multi-block parsing";
      checkInt "parsePem returns 3 certs" (3, List.length all)
    end

  fun run () =
    ( suiteParseFields ()
    ; suiteValidity ()
    ; suiteExtensions ()
    ; suiteAlgAndKey ()
    ; suiteVerify ()
    ; suiteTamper ()
    ; suiteChain ()
    ; suiteTimeCompare ()
    ; suitePemMulti () )
end
