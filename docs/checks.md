# Check catalog

| Check | Behavior | Limit |
|---|---|---|
| HTTPS and headers | Reviews HSTS, CSP, nosniff, Referrer-Policy, Permissions-Policy, and frame-embedding controls. | Checks observed responses; policy quality needs human review. |
| Cookie attributes | Checks Secure, HttpOnly, and SameSite without recording values. | Cookie names are evidence; cookie values are never included. |
| CORS | Sends Origin: https://webguard.invalid and checks wildcard or reflected credentialed access. | One test origin and the supplied root URL only. |
| HTTP methods | Sends OPTIONS and flags advertised TRACE, PUT, DELETE, and CONNECT. | Does not invoke those methods; Allow is not proof the method works. |
| Same-origin crawl | Follows a bounded set of same-scheme, same-host, same-port HTML links. | Skips obvious state-changing link names, static files, and query links with secret-like parameter names. Redirects are not followed. |
| Forms | Reviews method, action scheme, password field types, and common CSRF field names. | Never submits forms; CSRF detection is heuristic. |
| Mixed content | Finds HTTP scripts, frames, stylesheets, and media referenced by HTTPS pages. | Inspects HTML only, up to 512 KiB per response. |
| Error disclosure | Looks for common database error and stack-trace signatures in HTML responses. | Signatures may be false positives; response excerpts are not stored. |
| Public metadata paths | Requests robots.txt, /.well-known/security.txt, openapi.json, swagger.json, /api-docs, and /swagger/. | Reports only status and content type; it does not inspect response bodies. |
| Active HTML reflection | With --active-probes, places a harmless angle-bracket marker in existing nonsensitive GET query parameters. | Does not execute script or event-handler payloads; reflection alone is not XSS proof. |
| Active SQL error signal | With --active-probes, places a single quote in existing nonsensitive GET query parameters and checks for database error signatures. | No boolean, time-delay, stacked-query, or data-extraction probes. A finding needs manual validation. |

The default scan has a global request cap, per-request timeout, inter-request delay, and page cap. Each request is standalone: redirect following, cookie reuse, authentication, and environment proxy use are disabled. Targets are limited to the supplied scheme, host, and port.
