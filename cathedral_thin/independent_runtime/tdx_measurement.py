"""Owner-controlled TDX measurement allowlist for the direct validator.

The pinned TDX verifier proves a quote came from genuine, up-to-date Intel
hardware and binds REPORT_DATA, and it emits ``measurement``: a SHA-256 over
TD attributes, XFAM, MRTD, MRCONFIGID, MROWNER, MROWNERCONFIG and RTMR0-3. It
does not decide which guest images are acceptable. Without this policy any TD
running any code on current hardware passes, which is the gap SNP already
closes with its ``allowed_measurements``.

The policy has two modes:

* ``shadow`` records each machine's measurement and whether it is allowed,
  and pays exactly as before, so operators can collect the fleet's
  measurements before turning enforcement on;
* ``enforce`` turns a QVL PASS whose measurement is not listed into FAIL, so
  that machine earns zero. When that machine is a miner's primary (the chain
  axon, which serves the fleet list), the whole fleet is excluded, as for any
  other failed primary: an unadmitted image does not vouch for other machines.

The value moves more often than "one image, one entry" suggests. RTMR0 can
vary with the VM shape (vCPUs and memory). RTMR1 covers the kernel and initrd,
so a guest package upgrade that rebuilds the initramfs changes it while MRTD
stays fixed (cathedral-sandbox docs/MRTD.md records ``apt full-upgrade`` plus
a Docker install doing exactly that). RTMR3 follows what the guest extends at
runtime. So a miner who patches their own guest drops out under enforce until
the new value is listed; start in shadow mode and list what the fleet reports.

The policy may list either of the pinned verifier's two values: the v1
``tdx-measurement-sha256`` measurement above, or the v2
``tdx-image-sha256`` image identity (``image_measurement``; cathedral-sandbox
docs/MRTD.md, "Image identity"), a SHA-256 over TD attributes, XFAM, MRTD and
RTMR0-3 only. v1 includes MROWNER, which GCP sets per VM, so two honest VMs
from one image have different v1 values there and only a v2 entry lists the
image (cathedral-sandbox #265). A machine is admitted when its v1 value or its
v2 value is listed. A verifier release from before the v2 identity emits no
``image_measurement``, so under such a pin v2 entries admit nothing.

The measurement is the pinned verifier's formula (``reference_measurement``
below). Every allowlist entry depends on it, so a new verifier pin must be
checked to produce the same values before it replaces
``MEASUREMENT_CONTRACT_QVL_DIGEST``.

Without ``CATHEDRAL_TDX_MEASUREMENT_POLICY`` (a path) nothing changes. The
policy is read once at start: edit it, or the env file, then restart the unit.

Operators generate the policy with cathedral-sandbox's ``cathedral
policy-registry export-measurement-policy``, from one release of the owner's
signed measurement list. The loader takes no extra keys, so that command
writes the release beside the policy in ``<policy path>.source.json``
(``MIRROR_SOURCE_SCHEMA``). ``read_policy_source`` reads that record so startup
can say which signed release the validator mirrors. It is advisory: it never
changes what the policy admits, and a missing or broken record never stops
the validator.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .owner_policy_file import read_owner_policy_file

POLICY_SCHEMA = "cathedral_tdx_measurement_policy_v1"
TDX_MEASUREMENT_POLICY_ENV = "CATHEDRAL_TDX_MEASUREMENT_POLICY"
MAX_POLICY_BYTES = 128 * 1024
MODES = ("shadow", "enforce")
# A v1 launch measurement or a v2 image identity.
MEASUREMENT = re.compile(r"tdx-(?:measurement|image)-sha256:[0-9a-f]{64}")
# The optional env file the unit reads. A bootstrap from before the policy
# existed has no EnvironmentFile line for it (docs/AUTO_UPDATE.md), so startup
# says when this file exists but the variable is unset.
TDX_MEASUREMENT_ENV_FILE = Path("/etc/cathedral-validator/direct-tdx-measurement.env")
# The verifier release whose measurement formula is the one below: the
# cathedral-tdx-verifier-v1.0.0 asset (sandbox 0658524), whose source carries
# the contract vector test (cmd/cathedral-tdx-verifier,
# TestMeasurementMatchesPythonContractVector). A test ties this to
# qvl.DIRECT_VALIDATOR_QVL_DIGEST, so moving the verifier pin fails until the
# new release is checked against that vector, or a known quote, and this is
# moved with it.
MEASUREMENT_CONTRACT_QVL_DIGEST = (
    "4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148"
)
MEASUREMENT_DOMAIN = b"cathedral-tdx-measurement-v1\0"
IMAGE_MEASUREMENT_DOMAIN = b"cathedral-tdx-image-v1\0"


_FIELD_LENGTHS = (8, 8, 48, 48, 48, 48, 48, 48, 48, 48)


def reference_measurement(fields: tuple[bytes, ...]) -> str:
    """The verifier's measurement over TD_ATTRIBUTES, XFAM, MRTD, MRCONFIGID,
    MROWNER, MROWNERCONFIG and RTMR0-3, in that order (sandbox docs/MRTD.md).

    Reference only, for tests and for checking a new verifier release: the
    validator never computes a measurement itself, it reads the pinned
    verifier's.
    """

    if tuple(len(field) for field in fields) != _FIELD_LENGTHS:
        raise ValueError("a TDX measurement needs the ten fields at their lengths")
    digest = hashlib.sha256(MEASUREMENT_DOMAIN + b"".join(fields)).hexdigest()
    return "tdx-measurement-sha256:" + digest


_IMAGE_FIELD_LENGTHS = (8, 8, 48, 48, 48, 48, 48)


def reference_image_measurement(fields: tuple[bytes, ...]) -> str:
    """The verifier's v2 image identity over TD_ATTRIBUTES, XFAM, MRTD and
    RTMR0-3, in that order (sandbox docs/MRTD.md, "Image identity").

    Reference only, like :func:`reference_measurement`.
    """

    if tuple(len(field) for field in fields) != _IMAGE_FIELD_LENGTHS:
        raise ValueError("a TDX image identity needs the seven fields at their lengths")
    digest = hashlib.sha256(IMAGE_MEASUREMENT_DOMAIN + b"".join(fields)).hexdigest()
    return "tdx-image-sha256:" + digest


class TdxMeasurementPolicyError(Exception):
    """The local TDX measurement policy is unreadable or malformed."""


@dataclass(frozen=True)
class TdxMeasurementPolicy:
    mode: str
    allowed_measurements: frozenset[str]
    digest: str
    # The signed list release this policy file was exported from, when its
    # ``.source.json`` record names this exact file (read_policy_source). Never
    # set by the loader, never part of the evidence document; the cycle's
    # operator summary reports it.
    registry_release: int | None = field(default=None, compare=False)

    @property
    def enforced(self) -> bool:
        return self.mode == "enforce"

    def admits(self, measurement: str | None, image_measurement: str | None = None) -> bool:
        """Whether the v1 measurement or the v2 image identity is listed."""

        return any(
            value is not None and value in self.allowed_measurements
            for value in (measurement, image_measurement)
        )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise TdxMeasurementPolicyError("TDX measurement policy repeats a JSON key")
        value[key] = item
    return value


def _safe_policy_bytes(path: Path) -> bytes:
    return read_owner_policy_file(
        path,
        max_bytes=MAX_POLICY_BYTES,
        error=TdxMeasurementPolicyError,
        unavailable="safe TDX measurement policy loading is unavailable",
        unreadable="TDX measurement policy is not a readable regular file",
        unsafe="TDX measurement policy must be root or operator owned, not group "
        "or world writable, and at most 128 KiB",
        too_large="TDX measurement policy exceeds its size bound",
        changed="TDX measurement policy changed while it was read",
    )


def load_tdx_measurement_policy(path: str | Path) -> TdxMeasurementPolicy:
    """Load ``{"schema", "mode", "allowed_measurements"}`` strictly."""

    raw = _safe_policy_bytes(Path(path))
    try:
        document = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TdxMeasurementPolicyError(
            "TDX measurement policy is not strict JSON"
        ) from exc
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "mode",
        "allowed_measurements",
    }:
        raise TdxMeasurementPolicyError(
            "TDX measurement policy must contain exactly schema, mode and allowed_measurements"
        )
    if document["schema"] != POLICY_SCHEMA:
        raise TdxMeasurementPolicyError("TDX measurement policy schema is unsupported")
    if document["mode"] not in MODES:
        raise TdxMeasurementPolicyError(
            "TDX measurement policy mode must be shadow or enforce"
        )
    measurements = document["allowed_measurements"]
    # Types first, so a mixed list is refused cleanly instead of failing to sort.
    if (
        not isinstance(measurements, list)
        or any(
            not isinstance(item, str) or MEASUREMENT.fullmatch(item) is None
            for item in measurements
        )
        or measurements != sorted(measurements)
        or len(set(measurements)) != len(measurements)
    ):
        raise TdxMeasurementPolicyError(
            "TDX measurement policy allowed_measurements must be a sorted, unique list "
            "of tdx-measurement-sha256:<64 hex> or tdx-image-sha256:<64 hex>"
        )
    if document["mode"] == "enforce" and not measurements:
        raise TdxMeasurementPolicyError(
            "an enforcing TDX measurement policy must allow at least one measurement"
        )
    return TdxMeasurementPolicy(
        mode=document["mode"],
        allowed_measurements=frozenset(measurements),
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


# cathedral-sandbox ``measurement_list.MIRROR_SOURCE_SCHEMA`` and the bound its
# export command reads an existing record with.
MIRROR_SOURCE_SCHEMA = "cathedral_measurement_list_mirror_v1"
SOURCE_SUFFIX = ".source.json"
MAX_SOURCE_BYTES = 64 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_REGENERATE = (
    "regenerate both files with cathedral policy-registry export-measurement-policy"
)


@dataclass(frozen=True)
class TdxMeasurementPolicySource:
    """What ``<policy path>.source.json`` says, for the startup event.

    ``source`` is ``recorded`` (the record parsed), ``unrecorded`` (there is
    none) or ``unreadable`` (it exists but was refused or malformed, and is
    ignored). ``matches`` is whether the record's ``policy_digest`` names the
    loaded policy file.
    """

    source: str
    registry_release: int | None = None
    registry_digest: str | None = None
    registry_valid_until: str | None = None
    matches: bool = False
    warnings: tuple[str, ...] = ()

    def event_fields(self) -> dict[str, object]:
        fields: dict[str, object] = {
            "source": self.source,
            "registry_release": self.registry_release,
            "registry_digest": self.registry_digest,
            "registry_valid_until": self.registry_valid_until,
        }
        if self.warnings:
            fields["warning"] = "; ".join(self.warnings)
        return fields


class _SourceError(Exception):
    pass


def _parse_source(raw: bytes) -> tuple[int, str, str, str]:
    try:
        document = json.loads(raw, object_pairs_hook=_strict_object)
    except (
        UnicodeDecodeError,
        ValueError,  # JSONDecodeError, and an integer past Python's digit limit
        RecursionError,  # 64 KiB of "[" nests too deep to parse
        TdxMeasurementPolicyError,
    ):
        raise _SourceError("is not strict JSON") from None
    if not isinstance(document, dict) or document.get("schema") != MIRROR_SOURCE_SCHEMA:
        raise _SourceError(f"is not a {MIRROR_SOURCE_SCHEMA} record")
    release = document.get("registry_release")
    registry_digest = document.get("registry_digest")
    policy_digest = document.get("policy_digest")
    valid_until = document.get("registry_valid_until")
    if isinstance(release, bool) or not isinstance(release, int) or release < 0:
        raise _SourceError("has no valid registry_release")
    for name, value in (
        ("registry_digest", registry_digest),
        ("policy_digest", policy_digest),
    ):
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise _SourceError(f"has no valid {name}")
    if not isinstance(valid_until, str) or _UTC_SECOND.fullmatch(valid_until) is None:
        raise _SourceError("has no valid registry_valid_until")
    try:
        datetime.strptime(valid_until, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise _SourceError("has no valid registry_valid_until") from None
    return release, registry_digest, policy_digest, valid_until


def read_policy_source(
    policy_path: str | Path,
    policy: TdxMeasurementPolicy,
    *,
    now: datetime | None = None,
) -> TdxMeasurementPolicySource:
    """Read ``<policy path>.source.json`` bounded, never raising.

    It goes through the policy's own reader (regular file, no symlink, no
    FIFO, owner and mode checks, at most 64 KiB). Its ``policy_digest`` is
    ``sha256:`` over the policy file's bytes, the same value as
    ``policy.digest``; a record naming another digest, or a list release past
    its ``registry_valid_until``, is reported with a warning.
    """

    path = Path(str(policy_path) + SOURCE_SUFFIX)
    try:
        raw = read_owner_policy_file(
            path,
            max_bytes=MAX_SOURCE_BYTES,
            error=_SourceError,
            unavailable="cannot be read safely on this platform",
            unreadable="is not a readable regular file",
            unsafe="must be a root or operator owned file, not group or world "
            "writable, of 1 byte to 64 KiB",
            too_large="exceeds 64 KiB",
            changed="changed while it was read",
        )
        release, registry_digest, policy_digest, valid_until = _parse_source(raw)
    except OSError:
        # A read error after the open; the record is advisory either way.
        return TdxMeasurementPolicySource(
            source="unreadable",
            warnings=(f"{path} could not be read; it is ignored; {_REGENERATE}",),
        )
    except _SourceError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return TdxMeasurementPolicySource(source="unrecorded")
        return TdxMeasurementPolicySource(
            source="unreadable",
            warnings=(f"{path} {exc}; it is ignored; {_REGENERATE}",),
        )
    warnings: list[str] = []
    matches = policy_digest == policy.digest
    if not matches:
        warnings.append(
            f"{path} records policy_digest {policy_digest}, not the loaded policy's"
            f" {policy.digest}, so registry_release {release} does not describe"
            f" this policy file; {_REGENERATE}"
        )
    expires = datetime.strptime(valid_until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    if (now or datetime.now(UTC)) >= expires:
        warnings.append(
            f"signed list release {release} expired at {valid_until}; {_REGENERATE}"
            " from a current release"
        )
    return TdxMeasurementPolicySource(
        source="recorded",
        registry_release=release,
        registry_digest=registry_digest,
        registry_valid_until=valid_until,
        matches=matches,
        warnings=tuple(warnings),
    )
