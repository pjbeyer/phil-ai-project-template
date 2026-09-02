# Project Provisioning Template

Versioned Copier template for a minimal repository operating layer. The provisioner—not this template—owns live Git, Beads, SpecKit, backup, Cron-manifest, and credential interactions.

## Render locally

```bash
copier copy --trust --defaults --data repository_owner=example --data repository_name=demo --data project_kind=generic --data template_revision=v0.1.0 . /tmp/demo
```

Supported `project_kind` values are `generic`, `macos-cli`, and `homebrew-tap`.

The template is intentionally language-neutral. It does not render application code, dependencies, `.beads/`, `.specify/`, credentials, backups, or workstation-specific state.
