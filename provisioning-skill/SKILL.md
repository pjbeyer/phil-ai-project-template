---
name: project-provisioning
description: "Use when Phil asks to create, provision, or bootstrap a new GitHub project repository from an empty origin. Defines the approved provisioning contract and runs deterministic simulations only; the retained LiveAdapter draft is fail-closed and no live provisioning path is implemented."
version: 0.2.2
platforms: [macos]
---

# Project provisioning

## Current availability: simulation only

The only available behavior is deterministic `FakeAdapter` simulation. The public CLI has no live selector, never constructs `LiveAdapter`, always identifies its result as simulation, and exits nonzero. It does not provision or inspect a live repository.

An internal Task-5 control plane now models inspect-only G02–G11 normalization and exact-gate resume using closed, typed operations and controlled disposable fakes. It accepts bounded raw JSON observations, derives parser-owned sanitized findings, and cryptographically binds every safely admitted full observation—including the current failed observation—using non-disclosing canonical payload digests. Unsafe, unavailable, or malformed observations fail closed and cannot authorize resume. It returns `verified-existing` only when every terminal invariant (including both Git and Dolt synchronization) passes, and otherwise identifies the first exact unproven gate. Inspection evidence is immutable and in-memory only. Resume binds that evidence ID plus request/config fingerprints and the next gate, repeats the same ordered inspection, requires the fresh full evidence snapshot and evidence ID to match exactly, and starts only that gate. This control plane is deliberately factory-gated for controlled tests and is not wired to `LiveAdapter` or the public CLI; it adds no live availability.

A separate private controlled-fixture boundary models G06 manifest append, G07 backup state, and the offline G08-C synthetic SpecKit handoff only for descriptor-pinned disposable temporary fixtures. The G08-C controller is factory-gated and single-use; it creates only the fixed synthetic `.specify` tree and fixture-local `G08-C`/`simulation` ledger, and revalidates the persisted G07 oracle before every mutation. Its closed two-module implementation permits only descriptor-relative fixture operations plus the fixed temporary-root bootstrap; it has no public-CLI or `LiveAdapter` wiring and invokes no real SpecKit, command, network, service, credential, Git, Beads, Dolt, Copier, manifest, backup, or origin operation. A ledger outcome is durable only after post-replace evidence-directory fsync plus exact stable-ledger readback; otherwise it returns unrecorded/indeterminate partial. Cooperative descriptor pinning constrains the test fixture; it is not a sandbox against hostile Python in the same process. G08-C approval remains a prerequisite for any future live-G08 work, and does not itself authorize it.

A rejected, incomplete `LiveAdapter` draft remains in source only as quarantined redesign reference. `_LIVE_EXECUTION_AVAILABLE = False` blocks it before runner/config validation, command construction, or runner invocation. It has no approved executor, credential path, or production transport and must not be represented as live-ready. Replacing it requires a closed operation-specific executor (no arbitrary argv), bounded raw outputs parsed by the adapter, minimal command environments and command-scoped credential providers, configuration-digest-bound authorization, mandatory sanitized evidence, inspect-only state discovery, exact gate-bound resume, controlled tests, independent review, and a separate approval. Until then, only simulation commands below are permitted.

Provisioning prerequisites describe a future supervised live workflow; supplying them does not enable live execution:

- credential-free `origin_url`;
- unused short lowercase `beads_prefix`;
- `project_kind`: `generic`, `macos-cli`, or `homebrew-tap`;
- optional non-secret description; and
- explicit authorization for the named live run.

## Authority boundary

This is a two-part system:

1. The separately versioned Copier source for stable repository files lives in the `project-provisioning-template` repository (the `pjbeyer/phil-ai-project-template` source). It is checked out wherever the operator works; this skill never hard-codes that absolute path.
2. A future replacement inside this skill will own live state transitions, evidence, and inspection only after implementation, controlled verification, independent review, and separate approval. It must not be replaced with a wrapper CLI.

The template never creates `.beads/`, `.specify/`, backup state, Cron state, credentials, host-specific paths, application source, dependency metadata, or language-specific tests. It renders only the operating layer and selected CI contract.

Use the template only from an approved immutable revision. Arbitrary template URLs are forbidden. Before a live render, capture the approved template tag and resolved commit in sanitized evidence.

## Future live workflow contract (not implemented)

The intended state machine is G01–G11:

| Gate | Check | Boundary after pass |
|---|---|---|
| G01 | request, owner routing, destination absence/containment, tools, credential-free origin, cloneability, central server, prefix | clone |
| G02 | clone primary `main`, reread remote identity | render |
| G03 | render immutable Copier revision and validate matrix | Beads |
| G04 | initialize Beads once in central server mode; read metadata | remote/hooks |
| G05 | configure/read credential-free HTTPS Dolt remote and intended hooks | manifest |
| G06 | compare-and-append one conflict-free manifest record, then coverage audit | backup |
| G07 | native backup init/sync and containment/ownership/mode/freshness checks | SpecKit |
| G08 | SpecKit Hermes-primary init plus compatible pack and focused constitution | bootstrap work |
| G09 | duplicate-search/create/readback bootstrap work | commit |
| G10 | rendered/state/hygiene validation and atomic conventional commit | push |
| G11 | push Git main, reread upstream equality, then `bd dolt push` evidence | completion |

### Safety rules

- G01 failure returns `blocked-preflight`: no mutation.
- G02–G11 failure returns `partial`: preserve state and evidence; no rollback, reinitialize, `--force`, destructive Beads flag, manifest overwrite, or automatic retry.
- A subsequent request first performs inspection only. It can mutate only when Phil explicitly authorizes the exact request fingerprint and failed gate. Revalidate every predecessor invariant and start at that gate.
- A complete inspected state returns `verified-existing` without mutation.
- Git and Dolt synchronization are distinct evidence fields. Neither one alone proves completion.
- Never start/stop/restart/reconfigure the shared Dolt listener. Use the existing server at `127.0.0.1:3307` only.
- Clear `BEADS_DOLT_PORT` and `BEADS_DOLT_DATABASE` only in a future approved executor's minimal Beads-command environment; no such executor is currently implemented.

## Required live-state contracts

- Route `flexapp` to `~/Projects/work/<repository>` and `pjbeyer` to `~/Projects/pjbeyer/<repository>`. Another owner requires Phil’s approved destination.
- Read the real Beads database from generated `.beads/metadata.json`; never infer it from the prefix.
- The global manifest is an append-only shared source of truth. Reject duplicate path/prefix/database, malformed state, and concurrent changes. Never modify an existing record.
- Backups live only at `<repository>/.beads/backup`, with `pjbeyer:staff`, directories `0700`, regular files `0600`, no symlinks, special files, or filesystem crossing.
- SpecKit uses `specify init --here --integration hermes --script sh`, compatible extensions `verify-tasks`, `spec-validate`, `red-team`, `cleanup`, `reconcile`, `checkpoint`, `security-review`; presets `command-density`, `explicit-task-dependencies`, `security-governance`. Exclude `verify`, `review`, and `jira`.
- Bootstrap Beads issues use stable markers: scope/README and first SpecKit spec, plus real CLI-test work for `macos-cli`, or first Formula/Cask, out-of-band Homebrew secret confirmation, and package lifecycle tests for `homebrew-tap`.

## Offline-first verification

The following runs the simulation-only harness; it must not be interpreted as live readiness or permission to execute external operations.

```bash
# From the template repository checkout (not a hard-coded path):
cd <template-repo-checkout>
python3 -m unittest discover -s tests -v

# From this skill's own directory (wherever it is installed):
cd <this-skill-directory>
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/*.py tests/*.py
```

Run a hygiene scan over changed source and generated render roots. Do not treat no test collection as success. Template render tests must cover all three kinds, expected/forbidden files, YAML/JSON validity, full-SHA action pins, absence of credentials/private paths, and no live-state artifacts.

## Live run gate

**Always-gated:** origin creation, credentials/Actions secrets, any shared-service/manifest/database recovery, and release/publication.

**Graduating:** live provisioning begins review-every-run. It may move to sampled review only after multiple documented clean, reversible, no-duplicate runs and a demonstrated recovery path. Any unsafe run reverts to review-every-run.

The provisioner is currently **simulation-only**. A rejected, incomplete
`LiveAdapter` draft is retained solely as a quarantined redesign reference;
`_LIVE_EXECUTION_AVAILABLE = False` blocks it before runner/config validation,
command construction, or runner invocation. It has no approved executor,
credential path, production transport, or live inspection path and cannot
satisfy live provisioning requirements or SC-003. `simulation-passed` is test
evidence only—not a provisioned repository, Git/Dolt synchronization, or
verification claim. Simulation marks G02–G11 evidence as `simulated`, leaves
`mutations_completed` empty, and exits non-zero so automation cannot mistake
an offline adapter exercise for success. Approval of redesign documents or
controlled tests does not authorize a live run; a production executor and any
real invocation require separate review and approval.

The template is independently versioned. Current revision `v0.1.4`
(resolved commit `82dc6eae0730f888bb66a00e061242fb5b7e59fd`), published at
`https://github.com/pjbeyer/phil-ai-project-template`. Tags
`v0.1.0`–`v0.1.2` carry a nonexistent release-please-action SHA pin
(remediated in `v0.1.3`; do not render from them). `v0.1.4` fixes the
`template_revision` default (it was `v0.1.0`, below the review floor) and
ships an installable `project-operating-baseline` agent skill at
`.agents/skills/project-operating-baseline/SKILL.md` so every rendered repo
carries the operating baseline. Until Copier reliably persists answers for
local source use, the supervised adapter must persist its own non-secret
provenance evidence (source, tag, resolved commit, and answers) and must not
claim FR-008/FR-019 completion from a render alone.


## Documentation and delivery

Update the template README and this skill with behavior changes. Keep template and skill commits separate and atomic. Before calling an implementation complete: run tests, review staged content for secret-shaped material and local paths, commit with Conventional Commits, push as authorized, and independently verify remote state.

## Installation (operator-side)

This skill is versioned in the public template repository
(`pjbeyer/phil-ai-project-template`) at the `provisioning-skill/` path and is
excluded from every Copier render — it provisions repositories, so it must be
installed *before* the repository it creates.

1. Choose an approved immutable revision (tag, or the resolved commit pinned to
   it) from the distribution history. Never install from a mutable ref.
2. Fetch the `provisioning-skill/` directory at that revision into the
   operator's agent skill root (e.g. the agent's `skills/` directory, keeping
   the directory name `project-provisioning`).
3. Configure `PROVISIONING_APPROVED_HOME` (or `approved_project_home` in the
   approved config file) to the operator's project root. The skill fails closed
   when neither is set.
4. Verify the installed copy: run `python3 -m unittest discover -s tests -v`
   from the skill directory and confirm the full suite passes before invoking
   it for provisioning.

A provenance mismatch (resolved commit does not match the approved tag) or a
failing installed-copy suite must stop installation.
