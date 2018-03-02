---
title: Semi-Static Diffie-Hellman Key Establishment for TLS 1.3
abbrev: TLS 1.3 Semi-Static KX
docname: draft-rescorla-semistatic-dh-latest
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


normative:
  RFC2119:

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
a mode of TLS 1.3 in which endpoints have a certified DH key which
is used to authenticate the exchange.





--- middle

# Introduction

TLS 1.3 {{!I-D.ietf-tls-tls13}} specifies a signed Diffie-Hellman
exchange modelled after SIGMA {{SIGMA}}. This design is suitable for
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
(EC)DH key is suitable. This document describes such a design modelled
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
  compute the traffic secrets. [Note: {{?I-D.cremers-cfrg-randomness-improvements}}
  describes a technique for accomplishing this with a signed exchange.]

* If the server has a comparatively slow signing cert (e.g., P-256)
  it can amortize that signature over a large number of connections
  by creating a delegated credential with an (EC)DH key from
  a faster group (e.g., X25519).

* Because there is no signature, the server has deniability for
  the existence of the communication. Note that it could always
  have denied the contents of the communication.

Note that this exchange is not generally faster than a signed
exchange if comparable groups are used. In fact, if delegated
credentials are used, it may be slower on the client as it has
to validate the delegated credential, though this operation
is cacheable.



# Security Considerations


--- back

