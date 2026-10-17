"""The validator-signed SEV-SNP roster the Cathedral API ingests (#1469 step 3).

The contract is polariscomputer PR #1473: docs/SNP_JOIN_ROSTER.schema.json
(copied to tests/fixtures/cathedral_validator_roster_v1.schema.json) and
polaris/services/cathedral_snp_roster.parse_roster, mirrored below as
``_api_parse`` so a schema drift on either side fails here.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import ipaddress
import json
import os
import re
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from bittensor_wallet import Keypair

import cathedral_thin.independent_runtime.direct_validator as runtime
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime import snp_roster as roster
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.direct_contract import (
    FinalizedMetagraphSnapshot,
)
from cathedral_thin.independent_runtime.fleet_score import MultiComputeRound
from cathedral_thin.independent_runtime.qvl import DIRECT_VALIDATOR_QVL_DIGEST

SCHEMA_FILE = (
    Path(__file__).parents[1] / "fixtures" / "cathedral_validator_roster_v1.schema.json"
)
NETUID = 584
NETWORK = "test"
VALIDATOR_KEY = Keypair.create_from_seed("0x" + "31" * 32)
OTHER_KEY = Keypair.create_from_seed("0x" + "32" * 32)
MINER_KEYS = [Keypair.create_from_seed("0x" + f"{40 + i:02x}" * 32) for i in range(2)]
MINERS = [key.ss58_address for key in MINER_KEYS]
AXONS = (
    ServingAxon(3, MINERS[0], "207.244.245.11", 8081),
    ServingAxon(5, MINERS[1], "207.244.245.12", 8081),
)
NOW = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)
BLOCK = 8230743
URL = "https://api.staging.invalid/v1/cathedral/snp/roster"
TOKEN = "roster-ingest-token-for-tests-only"


# ---- the API's intake, ported from cathedral_snp_roster.parse_roster (PR #1473)


class _Rejected(Exception):
    pass


_API_TOP = {
    "schema",
    "network",
    "netuid",
    "validator",
    "sequence",
    "block",
    "generated_at",
    "rows",
    "roster_id",
    "signature",
}
_API_ROW = {"uid", "hotkey", "endpoint", "machine_id"}


def _api_int(value, low, high):
    return type(value) is int and low <= value <= high


def _api_endpoint(value):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 255
    ):
        raise _Rejected("endpoint invalid")
    parsed = urlsplit(value)
    port = parsed.port
    address = ipaddress.ip_address(parsed.hostname or "")
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not port
        or not address.is_global
    ):
        raise _Rejected("endpoint must be an HTTPS origin on a public IP literal")


def _api_canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _api_parse(raw, *, pinned, network=NETWORK, netuid=NETUID, now=NOW, max_age=1800):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise _Rejected("duplicate keys")
            result[key] = value
        return result

    def no_float(_):
        raise _Rejected("roster numbers must be integers")

    assert 0 < len(raw) <= 256 * 1024
    document = json.loads(
        raw, object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_float
    )
    if (
        set(document) != _API_TOP
        or document["schema"] != "cathedral_validator_roster_v1"
    ):
        raise _Rejected("roster fields invalid")
    if document["network"] != network or document["netuid"] != netuid:
        raise _Rejected("roster names another chain")
    validator = document["validator"]
    if set(validator) != {"uid", "hotkey"} or not _api_int(validator["uid"], 0, 65535):
        raise _Rejected("roster validator invalid")
    if validator["hotkey"] not in pinned:
        raise _Rejected("roster validator is not pinned")
    if not _api_int(document["sequence"], 0, 2**62) or not _api_int(
        document["block"], 0, 2**62
    ):
        raise _Rejected("roster sequence/block invalid")
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", document["generated_at"]
    ):
        raise _Rejected("roster time invalid")
    generated = datetime.strptime(
        document["generated_at"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=UTC)
    if not now - timedelta(seconds=max_age) <= generated <= now + timedelta(seconds=60):
        raise _Rejected("roster is not fresh")
    rows = document["rows"]
    if not isinstance(rows, list) or len(rows) > 256:
        raise _Rejected("roster rows invalid")
    for row in rows:
        if (
            set(row) != _API_ROW
            or not _api_int(row["uid"], 0, 65535)
            or not re.fullmatch(r"[0-9a-f]{64}", row["machine_id"])
        ):
            raise _Rejected("roster row invalid")
        Keypair(ss58_address=row["hotkey"])
        _api_endpoint(row["endpoint"])
    for field in ("machine_id", "endpoint"):
        if len({row[field] for row in rows}) != len(rows):
            raise _Rejected("roster repeats a " + field)
    if rows != sorted(rows, key=lambda r: (r["uid"], r["machine_id"], r["endpoint"])):
        raise _Rejected("roster rows are not in canonical order")
    body = {k: v for k, v in document.items() if k not in {"roster_id", "signature"}}
    if (
        document["roster_id"]
        != "sha256:" + hashlib.sha256(_api_canonical(body)).hexdigest()
    ):
        raise _Rejected("roster identity differs from its content")
    signature = document["signature"]
    if (
        set(signature) != {"algorithm", "value_base64"}
        or signature["algorithm"] != "sr25519"
    ):
        raise _Rejected("roster signature invalid")
    try:
        value = base64.b64decode(signature["value_base64"], validate=True)
    except (binascii.Error, ValueError):
        raise _Rejected("roster signature invalid") from None
    if (
        len(value) != 64
        or base64.b64encode(value).decode("ascii") != signature["value_base64"]
    ):
        raise _Rejected("roster signature invalid")
    message = b"cathedral-validator-roster-v1\x00" + document["roster_id"].encode(
        "ascii"
    )
    if not Keypair(ss58_address=validator["hotkey"]).verify(message, value):
        raise _Rejected("roster signature verification failed")
    return document


def _schema_check(document):
    """The required fields, closed objects and patterns of the published schema."""

    schema = json.loads(SCHEMA_FILE.read_text())
    props = schema["properties"]
    ss58 = schema["$defs"]["ss58"]["pattern"]
    assert set(document) == set(schema["required"])
    assert document["schema"] == props["schema"]["const"]
    assert document["network"] in props["network"]["enum"]
    assert set(document["validator"]) == set(props["validator"]["required"])
    assert re.fullmatch(ss58, document["validator"]["hotkey"])
    assert re.search(props["generated_at"]["pattern"], document["generated_at"])
    assert re.search(props["roster_id"]["pattern"], document["roster_id"])
    assert set(document["signature"]) == set(props["signature"]["required"])
    assert (
        document["signature"]["algorithm"]
        == props["signature"]["properties"]["algorithm"]["const"]
    )
    row_schema = props["rows"]["items"]
    assert len(document["rows"]) <= props["rows"]["maxItems"]
    for row in document["rows"]:
        assert set(row) == set(row_schema["required"])
        assert re.search(
            row_schema["properties"]["endpoint"]["pattern"], row["endpoint"]
        )
        assert re.search(
            row_schema["properties"]["machine_id"]["pattern"], row["machine_id"]
        )
        assert re.fullmatch(ss58, row["hotkey"])


# ---- round fixtures


def _machine_id(index: int) -> str:
    return hashlib.sha256(b"chip-%d" % index).hexdigest()


def _row(uid: int, index: int, *, tee_kind: str = "sev_snp", paid: bool = True) -> dict:
    hotkey = MINERS[0] if uid == 3 else MINERS[1]
    return {
        "uid": uid,
        "hotkey": hotkey,
        "endpoint": f"https://207.244.245.{11 + index}:8081",
        "ok": True,
        "tee_kind": tee_kind,
        "verdict": "PASS" if paid else "FAIL",
        "platform_identity_verified": paid,
        "sat_rule": SAT_WORK_UNIT_RULE,
        "sat_units": 20 if paid else 0,
        "counted_units": 20 if paid else 0,
        "channel_id": f"channel-{index}",
        "machine_id": _machine_id(index)
        if tee_kind == "sev_snp"
        else f"tdx-machine-{index}",
    }


ROWS = (
    _row(5, 2),  # out of order on purpose: the roster sorts
    _row(3, 0),
    _row(3, 1, tee_kind="tdx"),  # paid, but not SNP: not listed
    _row(5, 3, paid=False),  # unpaid: not listed
)


def _round(*rows: dict) -> MultiComputeRound:
    paid = [row for row in rows if row["counted_units"]]
    units: dict[str, int] = {}
    for row in paid:
        units[row["hotkey"]] = units.get(row["hotkey"], 0) + int(row["counted_units"])
    return MultiComputeRound(
        rows=tuple(dict(row) for row in rows),
        fleet=tuple(
            {
                "uid": axon.uid,
                "hotkey": axon.hotkey,
                "primary": f"https://{axon.ip}:{axon.port}",
                "ok": True,
                "singleton_compatibility": False,
                "candidate_count": 2,
                "endpoints": [
                    row["endpoint"] for row in rows if row["uid"] == axon.uid
                ],
            }
            for axon in AXONS
        ),
        verified_units=units,
        pass_count=len(paid),
        qvl_infra_count=0,
        feature_blocked=False,
        exclusions=(),
        blockers=(),
    )


def _snapshot() -> FinalizedMetagraphSnapshot:
    return FinalizedMetagraphSnapshot(
        block_number=BLOCK,
        block_hash="0x" + "b" * 64,
        validator_uid=7,
        validator_hotkey=VALIDATOR_KEY.ss58_address,
        miners=AXONS,
        skipped_axons={"refuse_or_canary": 0, "port_zero": 0, "unusable_ip": 0},
        netuid=NETUID,
    )


def _healthy() -> tuple[dict, ...]:
    return runtime._positive_machine_rows(_round(*ROWS), AXONS)


def _signed(**changes) -> dict:
    options = dict(
        healthy_rows=_healthy(),
        network=NETWORK,
        netuid=NETUID,
        block_number=BLOCK,
        validator_uid=7,
        validator_hotkey=VALIDATOR_KEY.ss58_address,
        generated_at=NOW,
    )
    options.update(changes)
    return roster.sign_snp_roster(
        roster.build_snp_roster(**options), keypair=VALIDATOR_KEY
    )


PINNED = frozenset({VALIDATOR_KEY.ss58_address})


# ---- schema and signature


def test_the_roster_matches_the_published_schema_and_the_api_intake():
    document = _signed()
    _schema_check(document)
    raw = roster._canonical(document)
    assert _api_parse(raw, pinned=PINNED) == document
    assert document["rows"] == [
        {
            "uid": 3,
            "hotkey": MINERS[0],
            "endpoint": "https://207.244.245.11:8081",
            "machine_id": _machine_id(0),
        },
        {
            "uid": 5,
            "hotkey": MINERS[1],
            "endpoint": "https://207.244.245.13:8081",
            "machine_id": _machine_id(2),
        },
    ]
    assert document["sequence"] == document["block"] == BLOCK
    assert document["validator"] == {"uid": 7, "hotkey": VALIDATOR_KEY.ss58_address}
    assert document["generated_at"] == "2026-10-17T12:00:00Z"


def test_an_empty_round_is_a_valid_roster():
    document = _signed(healthy_rows=())
    _schema_check(document)
    assert _api_parse(roster._canonical(document), pinned=PINNED)["rows"] == []


def test_the_api_refuses_an_edited_or_foreign_roster():
    document = _signed()
    edited = json.loads(json.dumps(document))
    edited["rows"][0]["endpoint"] = "https://8.8.8.8:8081"
    with pytest.raises(_Rejected, match="identity"):
        _api_parse(roster._canonical(edited), pinned=PINNED)
    edited["roster_id"] = roster.roster_id(edited)
    with pytest.raises(_Rejected, match="signature"):
        _api_parse(roster._canonical(edited), pinned=PINNED)
    with pytest.raises(_Rejected, match="not pinned"):
        _api_parse(
            roster._canonical(document), pinned=frozenset({OTHER_KEY.ss58_address})
        )
    with pytest.raises(_Rejected, match="another chain"):
        _api_parse(
            roster._canonical(document), pinned=PINNED, network="finney", netuid=94
        )


def test_only_the_named_validator_hotkey_signs():
    unsigned = roster.build_snp_roster(
        healthy_rows=_healthy(),
        network=NETWORK,
        netuid=NETUID,
        block_number=BLOCK,
        validator_uid=7,
        validator_hotkey=VALIDATOR_KEY.ss58_address,
        generated_at=NOW,
    )
    with pytest.raises(roster.SnpRosterError, match="signer"):
        roster.sign_snp_roster(unsigned, keypair=OTHER_KEY)
    tampered = {**unsigned, "block": BLOCK + 1}
    with pytest.raises(roster.SnpRosterError, match="identity"):
        roster.sign_snp_roster(tampered, keypair=VALIDATOR_KEY)


@pytest.mark.parametrize(
    "change",
    [
        {"machine_id": "A" * 64},
        {"machine_id": "short"},
        {"endpoint": None},
        {"uid": True},
    ],
)
def test_a_paid_snp_row_the_api_would_refuse_fails_the_roster(change):
    row = {**_row(3, 0), **change}
    with pytest.raises(roster.SnpRosterError):
        roster.build_snp_roster(
            healthy_rows=(row,),
            network=NETWORK,
            netuid=NETUID,
            block_number=BLOCK,
            validator_uid=7,
            validator_hotkey=VALIDATOR_KEY.ss58_address,
            generated_at=NOW,
        )


def test_the_roster_refuses_more_rows_than_the_api_accepts():
    rows = [
        {
            **_row(3, 0),
            "machine_id": f"{i:064x}",
            "endpoint": f"https://8.8.{i // 250}.{i % 250 + 1}:8081",
        }
        for i in range(roster.MAX_ROSTER_ROWS + 1)
    ]
    with pytest.raises(roster.SnpRosterError, match="more rows"):
        roster.build_snp_roster(
            healthy_rows=rows,
            network=NETWORK,
            netuid=NETUID,
            block_number=BLOCK,
            validator_uid=7,
            validator_hotkey=VALIDATOR_KEY.ss58_address,
            generated_at=NOW,
        )


def test_the_network_names_only_finney_or_test():
    with pytest.raises(roster.SnpRosterError, match="network"):
        _signed(network="testnet")


# ---- transport


class _Response:
    def __init__(self, status=202, body=None, content_type="application/json"):
        self.status = status
        self.body = body
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def getcode(self):
        return self.status

    def read(self, _limit):
        return self.body


class _Opener:
    def __init__(self, response=None, error=None):
        self.requests = []
        self.response = response
        self.error = error

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        if self.error is not None:
            raise self.error
        return self.response


def _ack(document, **changes):
    body = {
        "accepted": True,
        "roster_id": document["roster_id"],
        "sequence": document["sequence"],
        "rows": len(document["rows"]),
        **changes,
    }
    return _Response(body=json.dumps(body).encode())


def test_the_post_carries_the_bearer_token_and_the_canonical_bytes():
    document = _signed()
    opener = _Opener(_ack(document))
    acknowledgement = roster.post_snp_roster(
        url=URL, document=document, token=TOKEN, opener=opener
    )
    assert acknowledgement["accepted"] is True
    ((request, timeout),) = opener.requests
    assert request.full_url == URL and request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer " + TOKEN
    assert request.get_header("Content-type") == "application/json"
    assert request.data == roster._canonical(document)
    assert timeout == roster.DEFAULT_TIMEOUT_SECONDS
    assert _api_parse(request.data, pinned=PINNED) == document


def test_the_post_requires_an_acknowledgement_of_this_exact_roster():
    document = _signed()
    for response in (
        _ack(document, roster_id="sha256:" + "0" * 64),
        _ack(document, accepted=False),
        _Response(body=b"<html>"),
        _Response(body=b"{}", content_type="text/html"),
        _Response(status=204, body=b""),
    ):
        with pytest.raises(roster.SnpRosterError):
            roster.post_snp_roster(
                url=URL, document=document, token=TOKEN, opener=_Opener(response)
            )


def test_a_refusal_reports_the_api_check_not_the_content():
    document = _signed()
    error = urllib.error.HTTPError(
        URL,
        422,
        "Unprocessable",
        {},
        io.BytesIO(
            json.dumps(
                {
                    "detail": {
                        "error": "roster_rejected",
                        "reason": "roster sequence is not newer",
                    }
                }
            ).encode()
        ),
    )
    with pytest.raises(
        roster.SnpRosterError, match=r"HTTP 422: roster sequence is not newer"
    ):
        roster.post_snp_roster(
            url=URL, document=document, token=TOKEN, opener=_Opener(error=error)
        )
    with pytest.raises(roster.SnpRosterError, match="unavailable"):
        roster.post_snp_roster(
            url=URL,
            document=document,
            token=TOKEN,
            opener=_Opener(error=urllib.error.URLError("down")),
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://api.staging.invalid/v1/cathedral/snp/roster",
        "https://user@api.invalid/x",
        "https://api.invalid/x?q=1",
    ],
)
def test_the_post_refuses_anything_but_a_plain_https_url(url):
    opener = _Opener(_ack(_signed()))
    with pytest.raises(roster.SnpRosterError, match="HTTPS"):
        roster.post_snp_roster(url=url, document=_signed(), token=TOKEN, opener=opener)
    assert opener.requests == []


# ---- configuration


def test_unset_means_off_and_silent():
    assert roster.snp_roster_from_environment({}) == (None, None)
    assert roster.snp_roster_from_environment({roster.ROSTER_URL_ENV: "  "}) == (
        None,
        None,
    )


@pytest.mark.parametrize(
    "environ",
    [
        {roster.ROSTER_TOKEN_FILE_ENV: "/etc/cathedral-validator/snp-roster.token"},
        {
            roster.ROSTER_URL_ENV: "http://api.invalid/v1/cathedral/snp/roster",
            roster.ROSTER_TOKEN_FILE_ENV: "/etc/cathedral-validator/snp-roster.token",
        },
        {roster.ROSTER_URL_ENV: URL},
        {roster.ROSTER_URL_ENV: URL, roster.ROSTER_TOKEN_FILE_ENV: "relative.token"},
    ],
)
def test_a_half_or_invalid_configuration_stays_off_and_says_so(environ):
    export, event = roster.snp_roster_from_environment(environ)
    assert export is None
    assert event["snp_roster"]["status"] == "DISABLED"


def test_a_complete_configuration_enables_the_export():
    export, event = roster.snp_roster_from_environment(
        {
            roster.ROSTER_URL_ENV: URL,
            roster.ROSTER_TOKEN_FILE_ENV: "/etc/cathedral-validator/snp-roster.token",
        }
    )
    assert export == roster.SnpRosterExport(
        url=URL, token_file=Path("/etc/cathedral-validator/snp-roster.token")
    )
    assert event == {"snp_roster": {"status": "ENABLED", "url": URL}}


# ---- the cycle


def _token_file(tmp_path: Path) -> Path:
    path = tmp_path / "snp-roster.token"
    path.write_text(TOKEN + "\n")
    os.chmod(path, 0o600)
    return path


def _cycle(monkeypatch, *, snp_roster=None, status="CONFIRMED"):
    receipt = SimpleNamespace(status=status, as_document=lambda: {"status": status})
    writer = SimpleNamespace(
        recover=lambda: None, submit=lambda plan, **_kwargs: receipt, netuid=NETUID
    )
    monkeypatch.setenv("CATHEDRAL_TESTNET", "1")
    monkeypatch.setattr(
        runtime, "finalized_serving_miners_snapshot", lambda *_args: _snapshot()
    )
    monkeypatch.setattr(
        runtime, "score_multicompute_round", lambda **_kwargs: _round(*ROWS)
    )
    return runtime.run_direct_cycle(
        subtensor=object(),
        keypair=VALIDATOR_KEY,
        verifier_adapter=SimpleNamespace(qvl_digest=DIRECT_VALIDATOR_QVL_DIGEST),
        writer=writer,
        report_recovery=lambda _event: pytest.fail("no recovery expected"),
        netuid=NETUID,
        snp_roster=snp_roster,
    )


def _no_network(monkeypatch):
    def refuse(*_args, **_kwargs):
        pytest.fail("the roster export made a network call while off")

    monkeypatch.setattr(roster.urllib.request, "build_opener", refuse)
    monkeypatch.setattr(roster.urllib.request, "urlopen", refuse)
    monkeypatch.setattr(roster, "post_snp_roster", refuse)


def test_off_by_default_the_cycle_makes_no_roster_call(monkeypatch):
    _no_network(monkeypatch)
    event = _cycle(monkeypatch)
    assert event["status"] == "CONFIRMED"
    assert "snp_roster" not in event
    assert event["wire_uids"] == [3, 5]


def _capture(monkeypatch):
    sent = []

    class _Built:
        def open(self, request, timeout):
            sent.append(request)
            return _ack(json.loads(request.data))

    monkeypatch.setattr(
        roster.urllib.request, "build_opener", lambda *_handlers: _Built()
    )
    return sent


@pytest.mark.parametrize("status", ["CONFIRMED", "COMMITTED"])
def test_a_cycle_posts_the_signed_roster_after_its_write(
    monkeypatch, tmp_path: Path, status
):
    sent = _capture(monkeypatch)
    export = roster.SnpRosterExport(url=URL, token_file=_token_file(tmp_path))
    event = _cycle(monkeypatch, snp_roster=export, status=status)
    assert event["status"] == status
    (request,) = sent
    posted = _api_parse(request.data, pinned=PINNED, now=datetime.now(UTC))
    assert request.get_header("Authorization") == "Bearer " + TOKEN
    assert event["snp_roster"] == {
        "status": "POSTED",
        "roster_id": posted["roster_id"],
        "sequence": BLOCK,
        "rows": 2,
    }
    assert [row["uid"] for row in posted["rows"]] == [3, 5]
    assert posted["network"] == "test" and posted["netuid"] == NETUID


def test_a_roster_failure_never_changes_the_cycle(monkeypatch, tmp_path: Path):
    def down(*_handlers):
        class _Down:
            def open(self, request, timeout):
                raise urllib.error.URLError("refused")

        return _Down()

    monkeypatch.setattr(roster.urllib.request, "build_opener", down)
    export = roster.SnpRosterExport(url=URL, token_file=_token_file(tmp_path))
    event = _cycle(monkeypatch, snp_roster=export)
    assert event["status"] == "CONFIRMED"
    assert event["snp_roster"] == {
        "status": "FAILED",
        "error": "roster API is unavailable",
    }
    assert event["wire_uids"] == [3, 5]


def test_a_token_file_that_is_not_owner_only_is_never_sent(monkeypatch, tmp_path: Path):
    sent = _capture(monkeypatch)
    token = _token_file(tmp_path)
    os.chmod(token, 0o644)
    event = _cycle(
        monkeypatch, snp_roster=roster.SnpRosterExport(url=URL, token_file=token)
    )
    assert event["snp_roster"]["status"] == "FAILED"
    assert "owner-only" in event["snp_roster"]["error"]
    assert sent == []
