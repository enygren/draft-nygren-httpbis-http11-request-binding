---
###
title: "HTTP/1.1 Request Smuggling Defense using Cryptographic Request Binding"
abbrev: "HTTP/1.1 Request Binding"
category: std

docname: draft-nygren-httpbis-http11-request-binding-latest
submissiontype: IETF
wg: httpbis
consensus: true
v: 3
area: WIT
keyword:
 - HRS
 - Request Smuggling
 - Request Binding

author:
 -
    fullname: Erik Nygren
    organization: Akamai Technologies
    email: erik+ietf@nygren.org
 -
    fullname: Mike Bishop
    organization: Akamai Technologies
    email: mbishop@evequefou.be

normative:
  RFC2104:
  RFC2119:
  RFC5705:
  RFC7301:
  RFC7627:
  RFC8174:
  RFC8446:
  RFC8941:
  RFC9110:
  RFC9112:

informative:
  RFC9113:
  RFC9114:
  RFC9261:
  RFC9421:
  I-D.vvv-tls-alps:
  I-D.ietf-tls-tlsflags:
  PROXY:
    target: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
    title: The PROXY protocol
    author:
      organization: HAProxy Technologies
    date: 2017
  HTTPSYNC:
    target: https://arxiv.org/abs/2510.09952
    title: "HTTP Request Synchronization Defeats Discrepancy Attacks"
    author:
      - name: Cem Topcuoglu
      - name: Kaan Onarlioglu
      - name: Steven Sprecher
      - name: Engin Kirda
      - organization: Northeastern University
    date: 2025-10
    seriesinfo:
      arXiv: "2510.09952"
...

--- abstract

HTTP/1.1 Request Binding adds new hop-by-hop request header fields that are cryptographically bound to requests and responses. The keys used are negotiated out-of-band from the HTTP datastream (such as via TLS Exporters). These header fields allow endpoints to detect and mitigate desynchronization attacks, such as HTTP Request Smuggling, that exist due to datastream handling differences.

--- middle

# Introduction

## Motivation {#motivation}

HTTP Request Smuggling is a class of desynchronization attack {{HTTPSYNC}} where a malicious endpoint can cause a chain of other endpoints to get confused about HTTP request framing due to attributes of the HTTP/1.1 protocol leading to ambiguities in interpretation and variations in implementation.  For example, if in a flow of:

~~~
    client => intermediate => origin
~~~

the client can send an HTTP request header field with two Content-Length header fields and a Body that contains a second smuggled HTTP request after one of the content lengths.  If the intermediate and origin interpret the request in different ways, the intermediate might think that there was one request while the origin thinks there are now two requests. Not only would the first request get smuggled past intermediate defenses, if there is a second real request (so a total of three requests if you include the smuggled one) then the intermediary might cache the contents of the smuggled response with the cache key of the third request.  There are nigh-infinite variations on this in HTTP/1.1 with frequent vulnerabilities being found and fixed.

While HTTP/2 and HTTP/3 are better ({{RFC9113}} {{RFC9114}}), conversions between HTTP versions can also be vectors for vulnerabilities here to creep in. Additionally, a malicious client could force an HTTP/1.1 connection to pollute shared resources (a cache or persistent connection) shared with other clients using newer HTTP protocols. Furthermore, the simplicity of HTTP/1.1 and large legacy code bases mean that there is extensive use of HTTP/1.1 in intermediaries such as reverse proxies in the ecosystem: origins themselves may have a proxy implementation fronting application servers, each of which having distinct HTTP implementations.

## Mitigation Overview

The key concept of this specification is for HTTP/1.1 endpoints (such as an intermediate and an origin) to be able to share information about their state (eg, which request/response they think they're parsing) in a way that is cryptographically bound to the hop-by-hop TLS connection. Since the attacker has no access to the key used for the cryptographic binding, this allows the endpoints to detect desynchronization and fail out but without needing changes to the HTTP/1.1 protocol itself. This shared key is then used to authenticate newly introduced hop-by-hop header fields, binding information in those header fields (which includes sequential request/response serial numbers) to the request. In the cases where requests or responses do become desynchronized the bound header fields will not match what is expected or will fail to validate.

While "Request Framing Confusion" attacks (such as HTTP Request Smuggling or HRS) are one of the most common forms of HTTP Processing Discrepancy attacks, other types of attacks such as Host Confusion can also cause problems. This specification focuses on the former, but as it evolves we may be able to extend the approach taken to defend against other forms of attacks such as Host Confusion and Path Confusion, as well as to protect header fields added by Intermediaries.

*(FOR DISCUSSION: How broadly do we want to scope this specification? How much do we include here, and how much do we leave hooks to enable future extension?)*

HTTP endpoints communicating HTTPS over TLS use TLS Exporters to obtain the key used for the binding ({{!RFC8446, Section 7.5}} {{!RFC5705}}), enabling both endpoints of a connection to securely derive this key out-of-band from the request flow in a way that can't be tampered with. The use of Request Binding header fields is also negotiated during the TLS handshake.

The key used for the binding is abstracted out, so proprietary implementations not using TLS can distribute the key in some other manner, such as in a preface attribute that could be added to the PROXY protocol {{PROXY}}.

## Illustrative Example

In an example HRS attack from a malicious client to an origin through an intermediary, the request might start out normally but the malicious client smuggles a second malicious request into the initial request (eg, due to a bug in the intermediate or due to the intermediate and origin interpreting the HTTP/1.1 protocol slightly differently).

*(TODO: Add a diagram)*

The net result is that the Intermediate and Origin get desynchronized as to how requests and responses line up. When the malicious client makes a second request, it gets back the response to the smuggled request, and a caching intermediary may actually cache the response to the smuggled request with the cache key of this second request. This means the attacker can not only bypass any controls the Intermediary may be implementing, but may also be able to poison its cache.

With the proposed mitigation, the Intermediary augments the first and second requests (from its perspective) with cryptographically protected hop-by-hop `Bound-Request` header fields indicating a serial number (e.g., 1 and 2). While the Origin is able to validate the header field in the first request, the smuggled request is missing the header field (and even if the attacker tried to add one it would fail validation). This allows the Origin to detect the desynchronization, enabling it to refuse to process the smuggled request and terminate the connection.

*(TODO: Add a diagram)*

Request Smuggling is a family of attacks with many variations. This is why it's necessary to include the request and response binding hop-by-hop header fields in both directions, as in some other variations it's possible for things to get reordered such that an Intermediate making request A with serial=1 might get back a response for a request C with serial=2 and needs to be able to fail on that as well, as well as any wide range of other similar cases of desynchronization.

The need for a cryptographic binding to the channel between the Intermediate and Server (eg, with TLS Exporters) is required to prevent the malicious client from including a fake request binding header field in what is being smuggled in (which by its nature may be invisible to the Intermediate due to some bug or vulnerability).


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Bound Request/Response Header Protocol

This specification introduces new hop-by-hop `Bound-Request` and `Bound-Response` header fields, which use {{!RFC8941}} structured fields. These header fields convey a request/response Serial number, additional attributes, and a cryptographic binding.

As these are hop-by-hop header fields they are added by the endpoints on the HTTP/1.1 persistent connection ({{!RFC9112}}). Below we refer to the endpoint making the request as the Client and the endpoint receiving the request and issuing a response as the Server. For most cases where this is deployed the Client will be an Intermediary.

Clients and Servers MUST NOT exchange `Bound-Request` and `Bound-Response` header fields unless they have mutually negotiated this protocol, either as described below in {{tls-negotiation}} or via some other out-of-band mechanism. If the Client and Server have negotiated using this protocol for a connection, they MUST send a `Bound-Request` and `Bound-Response` header fields in all requests and responses on that connection.

## Request/Response Serials {#serials}

The Request Serial (`$req_serial`) is a counter starting at 1 for the initial request in an HTTP/1.1 persistent connection, and then incrementing by 1 for each subsequent request. The Response Serial (`$resp_serial`) for a response is then reflected back to match the Request Serial from the corresponding request.

## Binding Key {#binding-key}

The Binding Key is a binary cryptographic value that is associated with the connection. Below we will refer to the binding key for requests as `$req_key` and the binding key for responses as `$resp_key`.

With HTTPS over TLS the binding keys MUST be derived as described in {{keying-from-tls-exporters}}.

## Header Specification {#header-spec}

The `Bound-Request` and `Bound-Response` header fields are specified as an integer item (the Serial) followed by a parameter list of items.

The ABNF is as follows:

~~~ abnf
bound_header      = bound_header_name ":" serial ";" OWS
                    "method=" method ";" OWS
                    "authority=" authority ";" OWS
                    ("response-code" = response_code ";" OWS)?
                    "binding=" binding_value
bound_header_name = "Bound-Request" | "Bound-Response"
serial            = sf-integer
method            = sf-string
authority         = sf-string
response_code     = sf-integer
binding_value     = sf-binary
~~~

*(TODO: restructure the ABNF to allow the parameter orders to vary)*

The binding value for a request or response with a given key (`$req_key` or `$resp_key`) and is constructed as:

~~~
   binding_value = HMAC-SHA256($key, $serial "|" $method "|" authority)
~~~

In the above:

* `$key` is the `$req_key` or `$resp_key`
* `$serial` is the request or response serial as a string
* `$method` is the HTTP request method associated with the request
* `$authority` is the normalized authority for the request  (as defined in {{!RFC9110, Section 7.2}}) and MUST match the value in the request's Host header field
* `$response_code` is the response code for the response
* The binding value construct uses HMAC-SHA256 ({{!RFC2104}})

For example, the header field added to the first request on a connection might be:

~~~
   Bound-Request: 1; method=POST; authority=www.example.com;
                  binding=:yYwktnfv9Ehgr+pvSTu67FuxxMuyCcb8K7tH9m/yrTE=:
~~~

## For Discussion: Additional Attributes to Bind?

*FOR DISCUSSION: Do we want to add in additional information to defend against additional sorts of attacks?*

Some options might include:

* Adding the `:path` as a parameter (or adding an attribute indicating that it should be considered included) and also binding it in.
* Including a list of header fields to bind in, and then use {{RFC9421}} HTTP Message Signatures or similar to protect them.

Adding more in does add more complexity and has more risks of compatibility issues.

## Client Request Handling {#client-req-handling}

Clients which have negotiated this protocol MUST add a `Bound-Request` header field with each request they make. If the Client is an Intermediary, it MUST first remove any `Bound-Request` header fields that it received. The `$req_serial` MUST start at 1 for the first request on a persistent connection, and MUST be incremented by 1 for each subsequent request.

## Server Request Handling {#server-req-handling}

Servers which have negotiated this protocol MUST validate the presence and contents of the `Bound-Request` header field prior to processing a request. Any failures MUST be detected early in request processing (such as during request parsing), and servers MUST immediately terminate the connection without returning an error response.

Validation checks MUST include:

* Confirmation that the `Bound-Request` header field is present
* Confirmation that the cryptographic binding hash matches what was expected
* Confirmation that the `$req_serial` matches what was expected, starting at 1 for the first request on the connection and incrementing by 1 for each subsequent request
* Confirmation that the authority and method match those in the request

If the server is an intermediary, it MUST remove the `Bound-Request` header field before constructing a request to the next-hop.

When constructing a response to the HTTP request the server MUST add a `Bound-Response` header field with a `$resp_serial` matching the `$req_serial` of the incoming request. If the Client is an Intermediary, it MUST first remove any `Bound-Response` header fields that it received.

## Client Response Handling {#client-resp-handling}

Clients which have negotiated this protocol MUST validate the presence and contents of the `Bound-Response` header field prior to processing a response. Any failures MUST be detected early in response processing (such as during response parsing), and clients MUST immediately terminate the connection without processing any data from the response.

Validation checks MUST include:

* Confirmation that the `Bound-Response` header field is present
* Confirmation that the cryptographic binding hash matches what was expected
* Confirmation that the `$resp_serial` matches the `$req_serial` of the request that the response is in-response to.
* Confirmation that the authority and method match those from the corresponding the request
* Confirmation that the `$response_code` matches that from the response (or interim response, as discussed in {{handling-1xx}})


If the client is an intermediary, it MUST remove the `Bound-Response` header field before constructing a response to the previous-hop.

## Handling 100 Continue and 103 Early Hints {#handling-1xx}

When using `100 Continue` and `103 Early Hints`, the `$req_serial` and `$resp_serial` MUST remain the same and match for all interim and final responses. Each interim response MUST contain a `Bound-Response` header field with a response-code parameter matching the response code of the interim response.

## Retrying Requests {#retry-handling}

Requests which are retried MUST be treated no differently than other forms of request with their `$req_serial` coming from the order of the request in a persistent connection. If a request is retried over a different connection a new `Bound-Request` header field MUST be reconstructed corresponding to the new connection.

## Handling TLS 1.3 Early Data {#tls13-0rtt}

*TODO: define how this works with TLS 1.3 0RTT as it adds additional wrinkles. While this maybe could be made to work there (eg, using the separate early exporter secret and a distinct space for request\_serials) {{RFC8446}}.*

# Use with HTTPS over TLS

## Negotiation {#tls-negotiation}

Since the `Bound-Request` header field is hop-by-hop header field it is not safe to send unless the client knows that recipient supports it, will process it, and then will remove it. Clients and servers MUST NOT send `Bound-Request` or `Bound-Response` header fields on connections where they have not negotiated this protocol.

Negotiation needs to happen out-of-band (e.g., at the TLS layer) due to the nature of the attacks this is trying to mitigate.

Options for negotiation include:

* ALPS (stalled/expired) {{I-D.vvv-tls-alps}}
* TLS Extension Flags (waiting on implementation) {{I-D.ietf-tls-tlsflags}}
* An all-new TLS extension specific to this purpose, which could also make it easier to version this protocol.

Note that the first two options only support TLS 1.3 {{!RFC8446}}. It would also be preferable for the mechanism here to negotiate the supported versions of this protocol.

Application Protocols (ALPN values, per {{RFC7301}}) other than "http/1.1" are not supported, and a server MUST NOT negotiate this Request-Binding protocol when negotiating an application protocol other than "http/1.1".

## Key Derivation using TLS Exporters {#keying-from-tls-exporters}

The `$req_key` and `$resp_key` are derived using TLS Exporters.

* For TLS 1.3 this is specified in {{!RFC8446, Section 7.5}}
* For TLS 1.2 this is specified in {{!RFC5705}}

Endpoints MAY support TLS 1.2 using {{!RFC5705}}, but if they do they MUST use an extended master secret ({{!RFC7627}}). Endpoints MUST NOT use this protocol for versions of TLS prior to 1.2.

The request and response keys are constructed for a connection with:

~~~
$req_key = TLS-Exporter("HTTP-Request-Binding", "request-"+$alpn, 256)
$resp_key = TLS-Exporter("HTTP-Request-Binding", "response-"+$alpn, 256)
~~~

The added context ensures that we get different keys derived for different negotiated ALPNs. When HTTP/1.1 was negotiated without an ALPN, `$alpn` SHALL be `http/1.1`.


# Security Considerations

## Handling detection of desynchronized connections

When an endpoint detects desynchronization (due to a missing or invalid Request Binding header field) it needs to consider itself to be in an unknown, inconsistent, and potentially adversary-controlled state. Any processing that happens past this point for this or other requests on the connection is dangerous and suspect, as nothing in the connection bytestream can be trusted at this point. Letting the request or response get past validation failures during parsing would leave the endpoint vulnerable and might execute smuggled instructions.

Returning an HTTP error response would be bad as this response would be desynchronized and could be cached. Just breaking the connection does not provide information to clients as to why things broke, but is preferable.

*TODO: explore if there may be a way to use a TLS alert to signal that badness happened to the other endpoint.*

## Logging failures

Endpoints SHOULD log information indicating why the request or connection failed, but they MUST take care about what they log as all information is suspect at this point.

Servers logging information from detected smuggled requests need to take care as all information is suspect. It is critical that validation (and fail-out) happens very early in handling the request, such as during the request/response parsing itself. Even logging things from the smuggled request must be handled very carefully.

## Use of keys negotiated out-of-band

With the use of TLS Exporters each connection gets a unique pair of `$req_key` and `$resp_key`. If an alternate mechanism is used by proprietary implementations to exchange these keys then they MUST be unique per connection. Otherwise an attacker who can get a request header reflected back from one connection might be able to replay it in another connection.

# Privacy considerations

Due to this protocol primarily being used between Intermediaries and Servers, information sent by the (intermediate) Client during the TLS handshake for negotiation does not cause privacy issues for end-users. If this protocol were to be extended into end-user Clients as well, more evaluation of privacy considerations would be warranted.


# IANA Considerations

*TODO: Add IANA considerations for the HTTP Headers, for TLS Exporter labels, and for the TLS extension details used for negotiation.*



--- back

# Appendix: Alternate Approaches and Similar Protocols

TLS Exporters are used in other protocols such as {{RFC9261}} (Exported Authenticators in TLS). While it is meant as a building block, it requires round-trips for some scenarios which would make it not suitable here.

# Acknowledgments
{:numbered="false"}

The authors would like to thank Kaan Onarlioglu, Rich Salz, Ben Kaduk, Uttaran Dutta, and others who have contributed to this proposal.
