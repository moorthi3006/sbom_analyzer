# Submission tracker

## Complete for the hackathon demo

- [x] Parse JSON and CSV SBOMs and visualise dependency relationships.
- [x] Use the supplied version-specific vulnerability dataset; unknown packages do not receive invented CVEs.
- [x] Protect state-changing browser actions with CSRF tokens.
- [x] Remove repository credentials and production debug mode.
- [x] Use unique upload filenames, size/component limits, and transaction rollback on failures.

## Next iteration

- [ ] Add an OSV/NVD advisory adapter with scheduled dataset refreshes.
- [ ] Persist scan snapshots so historical reports retain their exact findings.
- [ ] Add user roles, audit logs, rate limiting, and deployment HTTPS configuration.
- [ ] Move large scans and graph rendering to a background worker.
