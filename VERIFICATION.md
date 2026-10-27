# Verification log

Last updated: 2026-10-27. "Verified" means checked against at least one public source on that date. Always re-check the vendor advisory before acting.

| Claim | Status | Notes |
|-------|--------|-------|
| Node.js 22.23.4 / 24.22.1 / 26.12.1 fix Brotli RCE (CVE-2026-111497) | Verified | nodejs.org advisory plus secondary reports; Node 20 and 25 are EOL, no fix |
| Apple: cert.pem backup and check commands | Verified | Matches support.apple.com/149555; removal commands not compared line by line |
| Firefox 158.0.1 or later | Verified | Mozilla/press reports |
| certifi 2026.10.19 or later | Verified | Secondary report |
| PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | Verified | Secondary report (Docker image tags) |
| Chrome 156.0.8078.47 or later | Verified | Corrected from .48; Chrome's eMudhra block shipped via CRLSet, no update needed |
| Bun 1.4.4 | UNVERIFIED | Check the Bun advisory |
| CPython 3.15.2 / 3.14.10 / 3.13.18 / 3.12.16 / 3.11.18 | UNVERIFIED | Check python.org |
| pip 26.2.2, uv 0.13.5 | UNVERIFIED | Check release notes |
| Tailscale 1.104.2 | UNVERIFIED | Check Tailscale security bulletins |
| Ruby 4.0.9 / 3.4.12 / 3.3.13 | UNVERIFIED | Check ruby-lang.org |
| Next.js 15.5.28 / 16.4.1, sharp 0.35.5 | UNVERIFIED | Check the Next.js advisory |
| Storybook 8.6.19 / 9.1.21 / 10.6.2 | UNVERIFIED | Check the GitHub advisory |
| Pillow 13.0.0, Brotli 1.2.1 | UNVERIFIED | Check release notes |
