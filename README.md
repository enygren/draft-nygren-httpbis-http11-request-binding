# IETF Draft: HTTP/1.1 Request Smuggling Defense using Cryptographic Request Binding

> Status: **Work In Progress (WIP)** – This repository hosts the editor’s copy of an Internet-Draft proposal. Content, structure, and filenames may change without notice prior to an initial (-00) submission and during early iterations.

## Abstract

HTTP/1.1 Request Binding adds new hop-by-hop request headers that are cryptographically bound to requests and responses. The keys used are negotiated out-of-band from the HTTP datastream (such as via TLS Exporters). These headers allow endpoints to detect and mitigate desynchronization attacks, such as HTTP Request Smuggling, that exist due to datastream handling differences.

## Live Draft Copies

Once GitHub Pages is enabled for this repository, the “Editor’s Copy” (latest main branch build) will be available here:

- Editor’s Copy (HTML):  
  https://enygren.github.io/draft-nygren-httpbis-http11-request-binding/draft-nygren-httpbis-http11-request-binding.html

- Editor’s Copy (Text):  
  https://enygren.github.io/draft-nygren-httpbis-http11-request-binding/draft-nygren-httpbis-http11-request-binding.txt


## Datatracker (After Formal Submission)

These links will become active only after the draft is first submitted (-00) to the IETF Datatracker:

- Datatracker main page:  
  https://datatracker.ietf.org/doc/draft-nygren-httpbis-http11-request-binding/

- Latest HTML rendition (canonical):  
  https://datatracker.ietf.org/doc/html/draft-nygren-httpbis-http11-request-binding
- Plain text:  
  https://www.ietf.org/archive/id/draft-nygren-httpbis-http11-request-binding-latest.txt

## Repository Layout (Template-Derived)

This repository is based on the [`martinthomson/internet-draft-template`](https://github.com/martinthomson/internet-draft-template). Key elements:

- Draft sources (Markdown or XML) in the root.
- GitHub Actions build & deployment workflows in `.github/workflows/`.
- The `gh-pages` branch holds the continuously updated editor’s copy and archive pages.
- Tagged versions (`draft-*` tags) trigger a publish workflow that can upload to the Datatracker.

## Building Locally

You need `make`, Python (for `xml2rfc` tooling via the template), and the template’s helper tooling (auto-handled by `make` targets).

```bash
# Build drafts (HTML, TXT, XML)
make

# Clean outputs
make clean
```

Outputs will appear as:
```
draft-nygren-httpbis-http11-request-binding.html
draft-nygren-httpbis-http11-request-binding.txt
draft-nygren-httpbis-http11-request-binding.xml
```

## Publishing a Versioned Draft

1. Update the draft’s `-NN` version identifier in the filename (if needed).
2. Tag the commit:
   ```bash
   git tag draft-nygren-httpbis-http11-request-binding-00
   git push origin draft-nygren-httpbis-http11-request-binding-00
   ```
3. (Optional) Manually dispatch `Publish New Draft Version` workflow with your submitter email.
4. Verify on the Datatracker after processing.

## Contributing / Scope

Early feedback—especially around is welcome. Please open issues or pull requests until this enters a working group flow.

## Disclaimer

This is **not** an adopted working group item (unless/ until stated otherwise). Content here does not represent consensus and may change substantially.

## License / Copyright

See [LICENSE.md](LICENSE.md). Contributions are assumed to conform to the IETF Note Well and relevant participation policies.

---

