---
title: Semi-Static Diffie-Hellman Key Establishment for TLS 1.3
abbrev: TLS 1.3 Semi-Static KX
docname: draft-rescorla-tls-semistatic-dh-latest
category: std

ipr: trust200902
area: General
workgroup: TLS Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: E. Rescorla
    name: Eric Rescorla
    organization: Mozilla
    email: ekr@rtfm.com
 -
    ins: N. Sullivan
    name: Nick Sullivan
    organization: Cloudflare
    email: nick@cloudflare.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: cawood@apple.com


normative:
  RFC2119:
  I-D.ietf-tls-tls13:
  I-D.ietf-httpbis-http2-secondary-certs:
  I-D.ietf-tls-exported-authenticator:

informative:
  SIGMA:
       title: "SIGMA: the 'SIGn-and-MAc' approach to authenticated Diffie-Hellman and its use in the IKE protocols"
       author:
       -
         ins: H. Krawczyk
       seriesinfo: Proceedings of CRYPTO 2003
       date: 2003
  KW16:
       title: "The OPTLS Protocol and TLS 1.3"
       date: 2016
       seriesinfo: Proceedings of Euro S&quot;P 2016
       target: https://eprint.iacr.org/2015/978
       author:
       -
         ins: H. Krawczyk
       -
         ins: H. Wee


--- abstract

TLS 1.3 {{!I-D.ietf-tls-tls13}} specifies a signed Diffie-Hellman
exchange modelled after SIGMA {{SIGMA}}. This design is suitable for
endpoints whose certified credential is a signing key, which is the
common situation for current TLS servers. This document describes
a mode of TLS 1.3 in which one or both endpoints have a certified
DH key which is used to authenticate the exchange.

--- middle

# Introduction

DISCLAIMER: This is a work-in-progress draft and has not yet seen
significant security analysis. Analysis of the modified TLS 1.3 -21
Tamarin model is currently underway. Thus, this draft should not be used as
a basis for building production systems.

TLS 1.3 {{!I-D.ietf-tls-tls13}} specifies a signed Diffie-Hellman
exchange modeled after SIGMA {{SIGMA}}. This design is suitable for
endpoints whose certified credential is a signing key, which is the
common situation for current TLS servers, which is why it was
selected for TLS 1.3.

However, it is also possible -- although currently rare -- for
endpoints to have a credential which is an (EC)DH key. This can happen
in one of two ways:

- They may be issued a certificate with an (EC)DH key, as specified
  for instance in {{!I-D.ietf-curdle-pkix}}
- They may have a signing key which they use to generate a delegated
  credential {{!I-D.ietf-tls-subcerts}} containing an (EC)DH key.

In these situations, a signed DH exchange is not appropriate, and
instead a design in which the server authenticates via its long-term
(EC)DH key is suitable. This document describes such a design modeled
on that described in OPTLS {{KW16}}.

This design has a number of potential advantages over the signed
exchange in TLS 1.3, specifically:

* If the end-entity certificate contains an (EC)DH key, TLS can
  operate with a single asymmetric primitive (Diffie-Hellman).
  The PKI component will still need signatures, but the TLS stack
  need not have one. Note that this advantage is somewhat limited
  if the (EC)DH key is in a delegated credential, but that allows
  for a clean transition to (EC)DH certificates.

* It is more resistant to random number generation failures on
  the server because the attacker needs to have both the server's
  long-term (EC)DH key and the ephemeral (EC)DH key in order to
  compute the traffic secrets. [Note: {{?I-D.irtf-cfrg-randomness-improvements}}
  describes a technique for accomplishing this with a signed exchange.]

* If the server has a comparatively slow signing cert (e.g., P-256)
  it can amortize that signature over a large number of connections
  by creating a delegated credential with an (EC)DH key from
  a faster group (e.g., X25519).

* Because there is no signature, the server has deniability for
  the existence of the communication. Note that it could always
  have denied the contents of the communication.

This exchange is not generally faster than a signed
exchange if comparable groups are used. In fact, if delegated
credentials are used, it may be slower on the client as it has
to validate the delegated credential, though the result
may be cached.

# Protocol Overview

The overall protocol flow remains the same as that in ordinary TLS 1.3,
as shown below:

~~~~
       Client                                               Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*         -------->
                                                       ServerHello  ^ Key
                                                      + key_share*  | Exch
                                                 + pre_shared_key*  v
                                             {EncryptedExtensions}  ^  Server
                                             {CertificateRequest*}  v  Params
                                                    {Certificate*}  ^
                                              {CertificateVerify*}  | Auth
                                                        {Finished}  v
                                 <--------     [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}                -------->
       [Application Data]        <------->      [Application Data]
~~~~

As usual, the client and server each supply an (EC)DH share in their
"key_share" extensions. However, in addition, the server supplies a
(signed) static (EC)DH share in its Certificate message, either directly
in its end-entity certificate or in a delegated credential. The client
and server then perform two (EC)DH exchanges:

- Between the client and server "key_share" values to form an
  ephemeral secret (ES). This is the same value as is computed
  in TLS 1.3 currently.

- Between the client's "key_share" and the server's static
  share, to form a static secret (SS).

Note that this means that the server's static secret MUST be in
the same group as selected group for the ephemeral (EC)DH exchange.

The handshake then proceeds as usual, except that:

* Instead of containing a signature, the CertificateVerify contains
  a MAC of the handshake transcript, computed based on SS.

* SS is mixed into the key schedule at the last HKDF-Extract
  stage (where currently a 0 is used as the IKM input).

# Negotiation

In order to negotiate this mode, we treat the (EC)DH MAC as if it were a
signature and negotiate it with a set of new signature scheme values:

~~~~
   enum {
     sig_p256(0x0901),
     sig_p384(0x0902),
     sig_p521(0x0903),
     sig_x52219(0x0904),
     sig_x448(0x0905),
   } SignatureScheme;
~~~~

When present in the "signature_algorithms" extension or
CertificateVerify.signature_scheme, these values indicate DH MAC with
the specified key exchange mode. These values MUST NOT appear
in "signature_algorithms_cert".

Before sending and upon receipt, endpoints MUST ensure that the
signature scheme is consistent with the ephemeral (EC)DH group
in use.

# Certificate Format

Like signing keys, static DH keys are carried in the Certificate
message, either directly in the EE certificate, or in a delegated
credential. In either case, the OID for the SubjectPublicKeyInfo
MUST be appropriate for use with (EC)DH key establishment. If
in a certificate, the key usage and EKU MUST also be set appropriately
See {{I-D.ietf-curdle-pkix}} and [[TBD: P-256, etc.]] for specific
details about these formats.

# Cryptographic Details

## Certificate Verify Computation

Instead of a signature, the server proves knowledge of the private
key associated with its static share by computing a MAC over the
handshake transcript using SS. The transcript thus far includes all
messages up to and including Certificate, i.e.:

~~~
Transcript-Hash(Handshake Context, Certificate)
~~~

The MAC key -- SS-Base-Key -- is derived from SS as follows:

~~~~
    SS-Base-Key = HKDF-Extract(0, SS)
~~~~

The MAC is then computed using the Finished computation described
in {{I-D.ietf-tls-tls13}} Section 4.4, with SS-Base-Key as the
Base Key value. Receivers MUST validate the MAC and terminate
the handshake with a "decrypt_error" alert upon failure.

Note that this means that the server sends two MAC computations in
the handshake, one in CertificateVerify using SS and the other in
Finished using the Master Secret. These MACs serve different
purposes: the first authenticates the handshake and the second proves
possession of the ephemeral secret.


## Key Schedule

The final HKDF-Extract stage of the TLS 1.3 key schedule has
an HKDF-Extract with the IKM of 0. When static key exchange
is negotiated, that 0 is replaced with SS, as shown below.

~~~~
...
           Derive-Secret(., "derived", "")
                 |
                 v
     SS -> HKDF-Extract = Master Secret
                 |
                 +-----> Derive-Secret(., "c ap traffic",
                 |                     ClientHello...server Finished)
                 |                     = client_application_traffic_secret_0
                 |
...
~~~~

# Early Data and Resumption

[[OPEN ISSUE]] It seems like one ought to be able to publish the server's static
key and use it for 0-RTT, but actually we don't know how to do the publication piece,
so I think we should leave this out for now.

# Client Authentication

[[OPEN ISSUE]] In principle, we can do client authentication the same way,
with the client's DH key in Certificate and a MAC in CertificateVerity.
However, it's less good because the client's static key doesn't get mixed
in at all. Also, client DH keys seem even further off.

# Security Considerations

[[OPEN ISSUE: This design requires formal analysis.]]

This is intended to have roughly equivalent security properties to current TLS 1.3,
except for the points raised in the introduction.

Open questions:

- Should semi-static key shares be mixed into the key schedule for client authentication?


# IANA Considerations

IANA [SHOULD add/has added] the new code points specified
in {{negotiation}} to the TLS 1.3 signature scheme registry, with
a "recommended" value of TBD.



--- back

