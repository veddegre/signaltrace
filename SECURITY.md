# Security Policy

## Supported Versions

Security fixes are applied to the current release only.

---

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

If you find a vulnerability, use GitHub's private vulnerability reporting feature (the "Report a vulnerability" button in the Security tab of this repository). If you'd prefer email, open a regular issue asking for a contact address and we'll respond with one.

A useful report includes a description of the vulnerability and its potential impact, steps to reproduce or a proof of concept, any relevant configuration context, and your suggested fix if you have one.

You can expect acknowledgement within 72 hours and a fix or mitigation plan within 14 days for confirmed issues. We're happy to credit you in the changelog and commit if you'd like that.

---

## Known Design Decisions

These are intentional design choices, not vulnerabilities:

**SignalTrace is built to receive hostile traffic.** It is a honeypot. Scanners, bots, and exploit probes hitting tracked paths are expected and logged by design.

**The admin interface uses HTTP Basic Auth over HTTPS.** The `/admin` path should never be publicly known or easily guessable. Consider IP-restricting it at the Apache level if your management IP is static.

**The SQLite database must not be web-accessible.** The `data/` directory must sit outside the document root or be protected by Apache configuration. Only `public/` should be served.

**The export API token appears in access logs if you use `?api_key=`.** Use the `Authorization: Bearer` header instead for any production automation.

---

## Hardening Recommendations

Beyond the production checklist in the README, a few things worth doing on active deployments:

Rotate `EXPORT_API_TOKEN` and `VISITOR_HASH_SALT` periodically. Watch Apache access logs for repeated 401s against `/admin` as an early signal of credential stuffing. Run `geoipupdate` on a weekly cron to keep GeoIP data fresh. If your management IP is static, an Apache `Require ip` directive on the `/admin` location is a meaningful additional layer.
