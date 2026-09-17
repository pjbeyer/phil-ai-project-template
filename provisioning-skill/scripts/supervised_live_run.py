#!/usr/bin/env python3
"""Supervised live-provisioning driver (library-level, not the public CLI).

Drives LiveAdapter gate-by-gate for one exact, Phil-authorized request. There is
no public selector: this is the reviewed supervision seam, not a new CLI flag.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.adapters import AdapterError, LiveAdapter
from scripts.evidence import request_fingerprint
from scripts.manifest import OWNING_JOBS
from scripts.preflight import normalize_request, parse_origin
from scripts.models import (
    ComponentPin,
    Gate,
    ImmutableLiveConfiguration,
    LiveAuthorization,
    ProvisioningRequest,
    configuration_digest,
)

# --- Phil-authorized T049 values (2026-09-13) -------------------------------
ORIGIN_URL = "https://github.com/pjbeyer/tmp-proj-1"
BEADS_PREFIX = "tmp1"
PROJECT_KIND = "macos-cli"
VISIBILITY = "personal-only"
DESCRIPTION = ""
TEMPLATE_SOURCE_IDENTITY = "pjbeyer/phil-ai-project-template"
TEMPLATE_TAG = "v0.1.4"
TEMPLATE_COMMIT = "82dc6eae0730f888bb66a00e061242fb5b7e59fd"  # v0.1.4
AGENT_CONTEXT_COMMIT = "6906bc582230bb752776e23287ee97990c1af743"  # spec-kit v1.0.3 (bundled CLI pin)

_POST_PREFLIGHT = [
    Gate.CLONE, Gate.RENDER, Gate.BEADS, Gate.BEADS_REMOTE, Gate.MANIFEST,
    Gate.BACKUP, Gate.SPECKIT, Gate.BOOTSTRAP, Gate.COMMIT, Gate.PUSH,
]


def build_authorization() -> tuple[LiveAuthorization, ImmutableLiveConfiguration]:
    pins = {
        "agent-context": ComponentPin(
            name="agent-context",
            source_identity="speckit/component/agent-context",
            resolved_commit=AGENT_CONTEXT_COMMIT,
        )
    }
    config = ImmutableLiveConfiguration.create(
        repository_identity="pjbeyer/tmp-proj-1",
        template_source_identity=TEMPLATE_SOURCE_IDENTITY,
        template_tag=TEMPLATE_TAG,
        resolved_template_commit=TEMPLATE_COMMIT,
        component_pins=pins,
    )
    # The fingerprint hashes only the *presence* of live_authorization (a bool),
    # not its value. To seal the authorization against the fingerprint the
    # adapter will recompute, fingerprint a request that already carries a
    # non-None authorization (a placeholder satisfies the presence flag).
    placeholder = ProvisioningRequest(
        origin_url=ORIGIN_URL,
        beads_prefix=BEADS_PREFIX,
        project_kind=PROJECT_KIND,
        description=DESCRIPTION,
        visibility=VISIBILITY,
        live_authorization=object(),  # presence-only; never admitted to prepare
    )
    origin, destination = normalize_request(placeholder)
    fingerprint = request_fingerprint(placeholder, destination)
    authz = LiveAuthorization(
        named_identity=origin.identity,
        request_fingerprint=fingerprint,
        config_digest=configuration_digest(config),
        permitted_starting_gate=Gate.PREFLIGHT,
    )
    return authz, config


def run(up_to: Gate | None) -> int:
    authz, config = build_authorization()
    request = ProvisioningRequest(
        origin_url=ORIGIN_URL,
        beads_prefix=BEADS_PREFIX,
        project_kind=PROJECT_KIND,
        description=DESCRIPTION,
        visibility=VISIBILITY,
        live_authorization=authz,
    )
    origin, destination = normalize_request(request)
    # Fingerprint the request as-submitted (live_authorization present), matching
    # the presence flag that was sealed into the authorization.
    fingerprint = request_fingerprint(request, destination)
    adapter = LiveAdapter(config=config)
    adapter.prepare(request, origin, destination, fingerprint)
    print(f"prepared: {origin.identity} -> {destination}")
    gates = [Gate.PREFLIGHT, *_POST_PREFLIGHT]
    if up_to is not None:
        gates = gates[: gates.index(up_to) + 1]
    for gate in gates:
        adapter.run_gate(gate)
        if gate is Gate.MANIFEST:
            # Mirror provision_project.py: G06 reserves, then the driver must
            # append the exact manifest record before BACKUP (G07) validates it.
            metadata = adapter.read_metadata()
            adapter.append_manifest({
                "path": str(destination), "prefix": request.beads_prefix,
                "database": metadata["dolt_database"], "owner": origin.owner,
                "project_kind": request.project_kind, "visibility": request.visibility,
                "profile": "default", "expected_remote": "origin", "expected_backup": True,
                "expected_sync": "manual-dolt-remote", "owning_jobs": sorted(OWNING_JOBS),
                "remote_health": "required", "restore_tier": "rotating",
            })
        print(f"{gate.value} OK: {adapter.gate_evidence(gate)}")
    print("ALL REQUESTED GATES PASSED")
    return 0


def main(argv: list[str]) -> int:
    up_to = None
    if len(argv) > 1 and argv[1].upper() in {g.value for g in Gate}:
        up_to = Gate(argv[1].upper())
    try:
        return run(up_to)
    except AdapterError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
