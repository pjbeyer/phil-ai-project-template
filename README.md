# Project Provisioning Template

Versioned Copier template for a minimal repository operating layer. The provisioner—not this template—owns live Git, Beads, SpecKit, backup, Cron-manifest, and credential interactions.

## Render locally

```bash
copier copy --trust --defaults --data repository_owner=example --data repository_name=demo --data project_kind=generic --data template_revision=v0.1.0 . /tmp/demo
```

Supported `project_kind` values are `generic`, `macos-cli`, and `homebrew-tap`.

The template is intentionally language-neutral. It does not render application code, dependencies, `.beads/`, `.specify/`, credentials, backups, or workstation-specific state.

## Install the operator-side provisioning skill

The operator-side provisioning skill is versioned in this repository at
`provisioning-skill/` and is excluded from every render (it provisions
repositories, so it must be installed *before* the repository it creates).

1. Choose an approved immutable revision (tag, or the resolved commit pinned to it).
2. Fetch `provisioning-skill/` at that revision into the operator's agent skill root (directory name `project-provisioning`).
3. Set `PROVISIONING_APPROVED_HOME` (or `approved_project_home` in the approved config file) to the operator's project root.
4. Verify: `python3 -m unittest discover -s tests -v` from the skill directory — the full suite must pass before use.

A provenance mismatch or a failing installed-copy suite must stop installation.
