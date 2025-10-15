<!-- regenerate: off (set to off if you edit this file) -->

# HTTP/1.1 Request Smuggling Defense using Cryptographic Request Binding

This is the working area for the individual Internet-Draft, "HTTP/1.1 Request
Smuggling Defense using Cryptographic Request Binding".

HTTP/1.1 Request Binding adds new hop-by-hop request headers that are
cryptographically bound to requests and responses. The keys used are negotiated
out-of-band from the HTTP datastream (such as via TLS Exporters). These headers
allow endpoints to detect and mitigate desynchronization attacks, such as HTTP
Request Smuggling, that exist due to datastream handling differences.

* [Editor's Copy](https://enygren.github.io/draft-nygren-httpbis-http11-request-binding/#go.draft-nygren-httpbis-http11-request-binding.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-nygren-httpbis-http11-request-binding)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-nygren-httpbis-http11-request-binding)
* [Compare Editor's Copy to Individual Draft](https://enygren.github.io/draft-nygren-httpbis-http11-request-binding/#go.draft-nygren-httpbis-http11-request-binding.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/enygren/draft-nygren-httpbis-http11-request-binding/blob/main/CONTRIBUTING.md).

The contributing file also has tips on how to make contributions, if you
don't already know how to do that.

## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

