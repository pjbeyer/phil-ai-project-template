# Render-contract evidence — three-kind disposable render

- **Date:** 2026-09-04
- **Template source:** local working tree (post `pjb-ltct` remediation; parent revision `802cd41`, tags `v0.1.0`–`v0.1.2` affected by the prior bad pin)
- **Suite:** `tests/test_render_contract.py` — `python3 -m unittest discover -s tests -v`
- **Runner:** Python 3.14, macOS, `copier` resolved via `PATH`

## Contracts verified

| Kind | Render | Files contract | Secrets scan | Workflow pins | Beads/SpecKit absence | Tagged update (v0.1.1 → v0.1.2) |
|---|---|---|---|---|---|---|
| `generic` | pass | pass | clean | pass (allowlist) | pass | pass |
| `macos-cli` | pass | pass | clean | pass (allowlist) | pass | pass |
| `homebrew-tap` | pass | pass | clean | pass (allowlist) | pass | pass |

## Result

`Ran 3 tests in 14.114s — OK`

## Notes

- Every rendered workflow `uses:` pin is asserted against `VERIFIED_ACTION_PINS` (a reviewed upstream SHA allowlist). Verified upstream references, checked against the GitHub API on 2026-09-04:
  - `googleapis/release-please-action@7987652d64b4581673a76e33ad5e98e3dd56832f` → tag `v4.1.3`
  - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` → tag `v4.2.2`
  - `Homebrew/actions/setup-homebrew@f1cc9df7a62b7f6244414d21a3ebc3ba9156a082` → real upstream commit 2026-04-24 (merge of PR #843); no tag anchor exists, so it is allowlisted as a verified commit with no tag claim
- Rendered trees contain no absolute local paths (the `assert_common` private-path check passed for all three kinds).
- Evidence is sanitized: no secrets, tokens, credentials, private absolute paths, or non-reproducible local identifiers are recorded here.
- Sanitized render evidence is intentionally the only persistent artifact; rendered fixtures themselves are disposable temp directories and are removed by the suite.
