# Security policy

## Scope and intended use

EvidEye is a research instrument for auditing web pages that **you own or are explicitly authorised to investigate** — your own domains, honeypots, samples shared by a CERT, or pages you have been engaged to assess.

It is not a scanner. Running it against third-party sites without permission is out of scope, and the design reflects that:

- `submit_intercepted` registers a Playwright `route` handler **before** the click, aborts the request, and records only the URL and payload that would have been sent. Submitted data never leaves the container.
- `fill_form_test` writes obviously fake values and never triggers a submission.
- `precheck/url_guard.py` rejects loopback, private, link-local and non-HTTP(S) targets before a browser is started (SSRF guard).
- Downloads are not implemented; nothing from the audited page is written to disk except screenshots and page-text extracts, which are kept under `static/evidence/`.

## Do not

- Do not remove or bypass the request interception to turn this into a form-submission tool.
- Do not run it at volume against hosts you do not control. Even aborted requests are requests.
- Do not publish `data/*.db`, `static/evidence/` or `static/reports/` — they contain real page content, screenshots and URLs. These paths are excluded by `.gitignore` for that reason.

## Credentials

API keys are read from the environment (`DASHSCOPE_API_KEY`, or the variable named in `config.yaml`'s `api_key_env`). No key is stored in this repository, and none should be committed. If you find a key in the tree or in git history, treat it as compromised, rotate it first, then report it.

## Isolation caveat

`isolation: l1` runs Chromium in a disposable Docker container and is the only mode that provides containment. `isolation: l2` is a hardened local browser — it reduces exposure but does **not** survive a browser exploit. Every report records which level was used.

## Reporting a vulnerability

Open a private security advisory on this repository, or email the maintainer. Please include the version, the isolation level in use, and a minimal reproduction. Do not open a public issue for anything that could be used to defeat the interception or the SSRF guard.

Expected response time: within 7 days.
