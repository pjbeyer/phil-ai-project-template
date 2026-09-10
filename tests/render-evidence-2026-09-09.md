# Render-contract evidence — three-kind disposable render (T044)

- **Date:** 2026-09-09
- **Template source:** local working tree at `72f28496` (post `pjb-m0ap.3.7` remediation; `provisioning-skill/v0.2.0` release tag)
- **Suite:** `tests/test_render_contract.py` — `python3 -m unittest tests.test_render_contract -v`
- **Runner:** Python 3.14, macOS, `copier` resolved via `PATH`

## Contracts verified

| Kind | Render | Files contract | Secrets scan | Workflow pins | Beads/SpecKit absence | provisioning-skill absence |
|---|---|---|---|---|---|---|
| `generic` | pass | pass | clean | pass (allowlist) | pass | pass |
| `macos-cli` | pass | pass | clean | pass (allowlist) | pass | pass |
| `homebrew-tap` | pass | pass | clean | pass (allowlist) | pass | pass |

## Result

`Ran 3 tests in 19.368s — OK`

## Notes

- Every rendered workflow `uses:` pin is asserted against the reviewed upstream-SHA allowlist (`VERIFIED_ACTION_PINS`); no mutable ref or AI-review action is accepted.
- Rendered trees contain no absolute local paths (private-path check passed for all three kinds).
- `provisioning-skill` remains excluded from every render (FR-026 render-absence assertion held).
- Evidence is sanitized: no secrets, tokens, credentials, private absolute paths, or non-reproducible local identifiers.