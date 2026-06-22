(* demo.sml -- parse a real RSA certificate chain and verify it.

   Uses the committed test fixtures (an OpenSSL-generated root -> intermediate
   -> leaf chain, plus the real ISRG Root X1), so the output is deterministic
   and byte-identical on every run and every compiler. *)

fun pr s = print (s ^ "\n")

fun one pem = hd (X509.parsePem pem)

val root  = one Fixtures.rootPem
val inter = one Fixtures.intermediatePem
val leaf  = one Fixtures.leafPem
val isrg  = one Fixtures.isrgRootX1Pem

fun cn n = case X509.commonName n of SOME s => s | NONE => "<none>"

fun showSigAlg a =
  case a of
    X509.Sha1WithRsa   => "sha1WithRSAEncryption"
  | X509.Sha256WithRsa => "sha256WithRSAEncryption"
  | X509.Sha384WithRsa => "sha384WithRSAEncryption"
  | X509.Sha512WithRsa => "sha512WithRSAEncryption"
  | X509.RsaPss _      => "rsassaPss"
  | X509.EcdsaWithSha256 => "ecdsa-with-SHA256"
  | X509.EcdsaWithSha384 => "ecdsa-with-SHA384"
  | X509.EcdsaWithSha512 => "ecdsa-with-SHA512"
  | X509.Ed25519Sig    => "Ed25519"
  | X509.UnknownSigAlg _ => "unknown"

fun showResult r =
  case r of
    X509.Verified => "Verified"
  | X509.Failed => "Failed"
  | X509.Unsupported why => "Unsupported (" ^ why ^ ")"

fun showChain r =
  case r of X509.ChainOk => "ChainOk" | X509.ChainError why => "ChainError: " ^ why

val () = pr "sml-x509 demo"
val () = pr "============="
val () = pr ""
val () = pr "Leaf certificate"
val () = pr ("  subject     : " ^ cn (X509.subject leaf))
val () = pr ("  issuer      : " ^ cn (X509.issuer leaf))
val () = pr ("  serial      : " ^ X509.serialHex leaf)
val () = pr ("  version     : v" ^ Int.toString (X509.version leaf + 1))
val () = pr ("  not before  : " ^ X509.timeToString (X509.notBefore leaf))
val () = pr ("  not after   : " ^ X509.timeToString (X509.notAfter leaf))
val () = pr ("  sig alg     : " ^ showSigAlg (X509.signatureAlg leaf))
val () = pr ("  is CA       : " ^ Bool.toString (X509.isCA leaf))
val () = pr ("  key usage   : " ^ String.concatWith ", " (X509.keyUsage leaf))
val () = pr ("  ext key use : " ^ String.concatWith ", " (X509.extKeyUsage leaf))
val () = pr ("  SAN dnsNames: " ^ String.concatWith ", " (X509.dnsNames leaf))

val () = pr ""
val () = pr "Signature verification (RSA, against the real issuer keys)"
val () = pr ("  leaf  <- intermediate : " ^
             showResult (X509.verifySignature { cert = leaf, issuer = inter }))
val () = pr ("  inter <- root         : " ^
             showResult (X509.verifySignature { cert = inter, issuer = root }))
val () = pr ("  root  (self-signed)   : " ^ showResult (X509.verifySelfSigned root))
val () = pr ("  ISRG Root X1 (self)   : " ^ showResult (X509.verifySelfSigned isrg))

val () = pr ""
val () = pr "Path validation (leaf -> intermediate -> trusted root)"
val now = { year = 2027, month = 1, day = 1, hour = 0, minute = 0, second = 0 }
val () = pr ("  at " ^ X509.timeToString now ^ " : " ^
             showChain (X509.verifyChain { cert = leaf, intermediates = [inter]
                                         , roots = [root], time = now }))
val expired = { year = 3000, month = 1, day = 1, hour = 0, minute = 0, second = 0 }
val () = pr ("  at " ^ X509.timeToString expired ^ " : " ^
             showChain (X509.verifyChain { cert = leaf, intermediates = [inter]
                                         , roots = [root], time = expired }))
