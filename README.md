# reconoscope_core

The core library containing the modules for reconoscope; a highly performant asynchronous OSINT tool built in Python.
It's designed to be fast, efficient, and easy to use, making it an ideal choice for security professionals and researchers looking to gather information quickly and effectively.

---

## About

This project is under active development, but should be usable in it's current state, reach out if you have any questions or find any bugs. The currently stable and implemented modules are highly optimized for performance.

## Modules

- **http**: A wrapper around httpx with built-in retry policies and rate limiting with randomized user agents, pre-configured _browser-like_ SSL context & verification, support for http2 and lower level socket configurations / tweaks for better performance.

- **certsh**: An asynchronous client for fetching subdomains from [crt.sh](https://crt.sh/), a popular certificate transparency log search engine with built in type safety, retries, and multiple concurrent domain searches.

- **dns**: An asynchronous DNS resolver using `dnspython` with built-in caching, retries, and support for multiple DNS servers. Built-in type safe support for A, AAAA, CNAME, MX, NS, TXT, and SOA records with specialized queries such as for reverse DNS lookups and email MX record discovery.

- **wmn**: Highly optimized asynchronous WhatsMyName username search client with support for custom username lists, multiprocessing and without any
  configuration supports 724+ websites. This module is insanely fast (_for python_) due to the implemented byte stream parsing.

## Setup

Since the project is still under active development, the reccommended way to install is via cloning the repository and installing the package in editable mode for the time being via uv

```bash
uv sync && \
uv build && \
uv pip install -e .
```

Then to see if it's working, run any of the demos in the `demos/` directory, for example

```bash
uv run demos/wmn.py
```

## Initial Release Goals

- Minimal port scanning module
- More OSINT modules such as for social media, breach data, etc.
- CLI frontend implementing library features
- Open directory checks
- WHOIS / RDAP parsing
- Gravatar hashing
- EXIF metadata extraction
- PDF / docx / xlsx metadata extraction
- Wayback machine archive lookups

### Web Surfacing / Crawling

- `.well-known` endpoint discovery for security.txt, robots.txt, etc.
- Client side javascript analysis for SSR "initial" context extraction common in
  modern web frame works (e.g `window.__INITIAL_STATE__` in React apps)
- Client-side dependency analysis for JS libraries and versions (e.g. jQuery 1.7.2)

### Stretch Goals

- Sitemap.xml parsing and crawling
- Client-side API endpoint discovery via static analysis of JS code
- CSP / CORS / Security header analysis
- Reverse CDN / hosting resolution
- TLS fingerprinting (JA3 / JA3S), not just the certs but the actual TLS handshakes
