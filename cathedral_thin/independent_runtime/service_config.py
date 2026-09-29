"""Validate the signed service's public mechanism configuration before wallet use.

This check never opens an accounting ledger, verifies a quote, or signs a weight.
Systemd runs it before ExecStart; an old or refusing runtime cannot start the
writer and the existing signed updater performs its normal readiness rollback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

from .delivery_plan import (
    MAX_BUNDLE_BYTES,
    MAX_RECEIPTS,
    DeliveryPlanError,
    policy_check,
)
from .qvl import DIRECT_VALIDATOR_QVL_DIGEST

SCHEMA = "cathedral_validator_service_config_v1"
OWNER_UID = 0
VERIFIER_PATH = "/opt/cathedral-validator/current/bin/cathedral-tdx-verifier"


def _public_json(path: Path, maximum: int) -> tuple[dict[str, Any], bytes]:
    if not path.is_absolute() or ".." in path.parts:
        raise DeliveryPlanError("service paths must be absolute and canonical")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != OWNER_UID
            or info.st_mode & 0o022
        ):
            raise DeliveryPlanError(
                "service input must be an owner-controlled regular file"
            )
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(maximum + 1)
    finally:
        os.close(fd)
    if len(raw) > maximum:
        raise DeliveryPlanError("service input exceeds limit")

    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise DeliveryPlanError("duplicate service JSON key")
            result[name] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise DeliveryPlanError("service input must be an object")
    return value, raw


def check(path: Path) -> dict[str, Any]:
    config, _raw = _public_json(path, 16384)
    if config.get("schema") != SCHEMA:
        raise DeliveryPlanError("service configuration schema differs")
    mode = config.get("mechanism")
    if mode == "sat":
        if set(config) != {"schema", "mechanism"}:
            raise DeliveryPlanError("SAT configuration cannot carry delivery inputs")
        return config
    if mode != "sn94_delivery_v1" or set(config) != {
        "schema",
        "mechanism",
        "policy_path",
        "policy_sha256",
        "bundle_path",
        "ledger_path",
    }:
        raise DeliveryPlanError("service mechanism configuration differs")
    for name in ("policy_path", "bundle_path", "ledger_path"):
        value = config[name]
        if (
            not isinstance(value, str)
            or not Path(value).is_absolute()
            or ".." in Path(value).parts
        ):
            raise DeliveryPlanError("delivery paths must be absolute and canonical")
    if (
        len(
            {
                str(path),
                config["policy_path"],
                config["bundle_path"],
                config["ledger_path"],
            }
        )
        != 4
    ):
        raise DeliveryPlanError("service inputs and ledger must have distinct paths")
    policy, raw = _public_json(Path(config["policy_path"]), 65536)
    policy = policy_check(policy)
    if (
        policy["mode"] != "write"
        or policy["verifier_path"] != VERIFIER_PATH
        or policy["verifier_sha256"] != DIRECT_VALIDATOR_QVL_DIGEST
        or hashlib.sha256(raw).hexdigest() != config["policy_sha256"]
    ):
        raise DeliveryPlanError(
            "delivery policy differs from configured write identity"
        )
    bundle, _ = _public_json(Path(config["bundle_path"]), MAX_BUNDLE_BYTES)
    if (
        set(bundle) != {"window_start", "uid_hotkeys", "entries"}
        or type(bundle["window_start"]) is not int
        or bundle["window_start"] < 0
        or bundle["window_start"] % policy["window_seconds"]
        or bundle["window_start"] + policy["window_seconds"] > int(time.time())
        or not isinstance(bundle["uid_hotkeys"], list)
        or not isinstance(bundle["entries"], list)
        or len(bundle["entries"]) > MAX_RECEIPTS
    ):
        raise DeliveryPlanError("delivery feed is not an explicit closed window")
    ledger = Path(config["ledger_path"])
    if ledger.is_symlink():
        raise DeliveryPlanError("delivery ledger cannot be a symlink")
    if ledger.exists():
        info = ledger.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise DeliveryPlanError("delivery ledger must remain private")
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cathedral-validator service-config-check")
    parser.add_argument("--config", type=Path, required=True)
    options = parser.parse_args(argv)
    try:
        config = check(options.config)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        DeliveryPlanError,
    ):
        print(json.dumps({"code": "service_config_refused", "chain_write": False}))
        return 2
    print(
        json.dumps(
            {
                "status": "CONFIGURED",
                "mechanism": config["mechanism"],
                "chain_write": False,
                "admission_checked": False,
            }
        )
    )
    return 0
