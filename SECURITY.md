# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Email the maintainer at the address listed on [github.com/abdimalikhussein25](https://github.com/abdimalikhussein25) with:

- a description of the issue and its impact
- steps or a proof of concept to reproduce it
- the version or commit you tested

You will get an acknowledgement within **72 hours** and a status update within **7 days**. Once a fix is released you'll be credited in the release notes, unless you prefer to stay anonymous.

## Scope

In scope: the scanner itself: unsafe parsing of remote responses, requests escaping the intended target, or report output that could inject content.

Out of scope: denial of service, social engineering, and issues in third-party services or dependencies (report those upstream).

## Supported versions

Only the latest release on `main` receives security fixes.
