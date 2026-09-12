"""Origin GitHub-visibility resolution (Slice L, FR-031).

A closed, transport-free resolver for the two-probe visibility sequence. The
adapter runs two ``git ls-remote`` probes (anonymous credential-detached and
authenticated credential-chain) and feeds their exit codes here; this module
maps the pair to a single closed result and owns the fail-closed policy.

Design principle (mirrors ``publish_hygiene.py``): this module holds no
subprocess, socket, or network authority — it only classifies the pair of exit
codes the adapter already observed. It is the single source of truth for the
four-way resolution matrix, so the same rule governs the live adapter and the
controlled test transport.
"""
from __future__ import annotations

from enum import Enum


class OriginVisibility(Enum):
    """The closed resolution of an origin-visibility probe pair."""

    PUBLIC = "public"
    PRIVATE = "private"
    UNREACHABLE = "unreachable"


class VisibilityResolutionError(ValueError):
    """Raised when the probe pair is contradictory or cannot resolve to a result."""


def resolve_origin_visibility(
    anonymous_ok: bool,
    authenticated_ok: bool,
) -> OriginVisibility:
    """Map two probe exit-status booleans to a closed visibility result.

    ``anonymous_ok`` is True when the credential-detached ``git ls-remote``
    exited 0 (the origin is publicly readable). ``authenticated_ok`` is True
    when the credential-chain probe exited 0 (the authenticated principal can
    read the origin — public, or private and principal-authorized).

    Resolution matrix (contract §3):

    - anonymous 0 + authenticated 0 -> PUBLIC
    - anonymous nonzero + authenticated 0 -> PRIVATE
    - anonymous 0 + authenticated nonzero -> impossible (contradiction) -> stop
    - anonymous nonzero + authenticated nonzero -> UNREACHABLE (stop, never
      downgrade to a private/public claim)

    A ``False``/``False`` pair is genuinely unreachable-or-absent and must stop;
    it is never assumed private. A ``True``/``False`` pair is a contradiction
    (a principal cannot fail to read a repo it can read anonymously) and stops.
    """
    if anonymous_ok and authenticated_ok:
        return OriginVisibility.PUBLIC
    if not anonymous_ok and authenticated_ok:
        return OriginVisibility.PRIVATE
    if anonymous_ok and not authenticated_ok:
        raise VisibilityResolutionError(
            "origin visibility is contradictory: anonymous-readable but "
            "authenticated-inaccessible"
        )
    # not anonymous_ok and not authenticated_ok
    return OriginVisibility.UNREACHABLE


def require_visibility_for(
    visibility: str,
    resolved: OriginVisibility,
) -> None:
    """Enforce the G11 pre-push visibility gate (FR-031d).

    ``visibility`` is the request's manifest-registry value (``personal-only`` /
    ``work-internal`` / ``open-source``). A non-``open-source`` request MUST
    resolve PRIVATE; an ``open-source`` request MUST resolve PUBLIC; any
    mismatch or UNREACHABLE stops the run.
    """
    if resolved is OriginVisibility.UNREACHABLE:
        raise VisibilityResolutionError("origin visibility could not be resolved")
    if visibility == "open-source":
        if resolved is not OriginVisibility.PUBLIC:
            raise VisibilityResolutionError(
                "open-source request requires a public origin"
            )
        return
    raise_on_public = visibility in ("personal-only", "work-internal")
    if not raise_on_public:
        # Unknown visibility: fail closed rather than assume private.
        raise VisibilityResolutionError(
            f"visibility {visibility!r} is outside the approved registry"
        )
    if resolved is not OriginVisibility.PRIVATE:
        raise VisibilityResolutionError(
            f"{visibility} request requires a private origin"
        )


def _self_test() -> int:
    assert resolve_origin_visibility(True, True) is OriginVisibility.PUBLIC
    assert resolve_origin_visibility(False, True) is OriginVisibility.PRIVATE
    assert resolve_origin_visibility(False, False) is OriginVisibility.UNREACHABLE
    try:
        resolve_origin_visibility(True, False)
    except VisibilityResolutionError:
        pass
    else:
        raise AssertionError("contradictory pair did not fail closed")

    require_visibility_for("personal-only", OriginVisibility.PRIVATE)
    require_visibility_for("work-internal", OriginVisibility.PRIVATE)
    require_visibility_for("open-source", OriginVisibility.PUBLIC)
    for bad in (
        ("personal-only", OriginVisibility.PUBLIC),
        ("personal-only", OriginVisibility.UNREACHABLE),
        ("open-source", OriginVisibility.PRIVATE),
    ):
        try:
            require_visibility_for(bad[0], bad[1])
        except VisibilityResolutionError:
            pass
        else:
            raise AssertionError(f"visibility gate did not stop for {bad}")
    try:
        require_visibility_for("not-a-real-visibility", OriginVisibility.PRIVATE)
    except VisibilityResolutionError:
        pass
    else:
        raise AssertionError("unknown visibility did not fail closed")

    print("self-test ok")
    return 0


if __name__ == "__main__":
    import sys

    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    raise SystemExit("library module")
