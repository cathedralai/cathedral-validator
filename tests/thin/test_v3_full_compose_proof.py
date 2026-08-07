"""Our validator code composes the full v3 vector — the launch gate.

At launch, root validators (tao.app / Yuma-tier) run *this* publisher code to
compose weights. So the thing that must be proven is not a one-off on a live
box: it is that ``build_signed_vector`` over a freshly-seeded store produces the
signed v3 (70% Intel-TDX / 30% CyberGym / 0% fixed burn) policy — crediting the
confidential TDX lane and the CyberGym solver — exactly as anyone running the
code would reproduce it.

``test_v3_compose_credits_the_cybergym_solver`` seeds one confidential report
(the TDX lane, uid163) and one *authenticated* CyberGym report (the solver,
uid250) the way a producer signs it, runs the real composer, and asserts the
signed ``validated_supply`` stamp, the 70/30 split, the uid-keyed CyberGym lane,
and zero fixed burn.

``test_missing_validated_supply_enabled_silently_falls_back`` pins the failure
that silently broke every live v3 attempt: without
``CATHEDRAL_VALIDATED_SUPPLY_ENABLED``, ``validated_supply_metadata()`` returns
``None`` and ``build_signed_vector`` never applies the contract at all — no v3
stamp, no CyberGym lane, just the flat-recent fallback. That flag is the whole
difference between a working cutover and a silent burn, so it gets a loud guard.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from scaffold.publisher import cybergym_contract, cybergym_ingest, external_scores, weights
from scaffold.publisher import mechanism_cybergym_adapter as adapter
from scaffold.publisher.store import Store

BURN = "5FBurnHotkeyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
UID163 = "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK"  # confidential TDX lane owner
UID250 = "5FCBM1y64aoDvuGWbDuerfPzzJNYWoXjofAjzVrnz3pYhFg3"  # cybergym solver
PRODUCER = "cathedral-cybergym-producer-sn39"
HMAC = "test-cybergym-hmac-secret"
EVIDENCE = "5c2d46477a942f632d9ccc380c318bcd5bd31cf7776ebdbc2b2492bf3b6117ab"

# The complete v3 environment. The one flag whose omission caused every live
# fallback (CATHEDRAL_VALIDATED_SUPPLY_ENABLED) is added separately so the
# negative test can drop exactly it.
V3_ENV = {
    "CATHEDRAL_WEIGHT_POLICY_NETWORK": "finney",
    "CATHEDRAL_WEIGHT_POLICY_NETUID": "39",
    "CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY": BURN,
    "CATHEDRAL_WEIGHT_POLICY_BURN_UID": "",  # v3 resolves burn by hotkey only
    "CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2": "0",  # v3 = exactly 0% fixed burn
    "CATHEDRAL_EXTERNAL_SCORES_ENABLED": "1",
    "CATHEDRAL_EXTERNAL_SCORES_SOURCE": "cathedral_confidential_tdx",
    "CATHEDRAL_EXTERNAL_SCORES_MODE": "confidential_primary",
    "CATHEDRAL_EXTERNAL_SCORES_PRIMARY_CONFIRM": "true",
    "CATHEDRAL_ALLOCATION_CONTRACT": "v3",
    "CATHEDRAL_CYBERGYM_MECHANISM_ENABLED": "1",
    "CATHEDRAL_CYBERGYM_WEIGHT_FRACTION": "0.30",
    "CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY": PRODUCER,
    "CATHEDRAL_CYBERGYM_SCORES_HMAC_SECRET": HMAC,
}


def _apply_env(monkeypatch, *, validated_supply_enabled: bool) -> None:
    for key, value in V3_ENV.items():
        monkeypatch.setenv(key, value)
    if validated_supply_enabled:
        monkeypatch.setenv("CATHEDRAL_VALIDATED_SUPPLY_ENABLED", "1")
    else:
        monkeypatch.delenv("CATHEDRAL_VALIDATED_SUPPLY_ENABLED", raising=False)


def _seed(store: Store, now: datetime) -> None:
    gen = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    epoch = int(now.timestamp())

    # Confidential TDX lane -> uid163, authenticated body bound like the intake does.
    conf = external_scores.normalize_report(
        {
            "source": "cathedral_confidential_tdx", "network": "finney", "netuid": 39,
            "epoch": epoch, "generated_at": gen, "complete": True,
            "scores": [{"miner_hotkey": UID163, "score": 1.0, "uid": 163}],
        },
        now=now,
    )
    conf = external_scores.bind_authenticated_body(conf, external_scores._canonical(conf))
    external_scores.store_report(store, conf)

    # CyberGym lane -> uid250. Signed over the SEMANTIC body exactly as a producer
    # signs the wire report, so the adapter's verify_stored_report accepts it.
    payload = {
        "producer_hotkey": PRODUCER, "network": "finney", "netuid": 39,
        "source_epoch": epoch, "generated_at": gen, "complete": True,
        "score_units": "level_weighted_verified_solves", "scores": {UID250: 2.0},
        "evidence_sha256": EVIDENCE,
    }
    body = cybergym_contract.canonical_report_bytes(
        cybergym_contract.normalize_semantic_document(payload)
    )
    signature = "sha256=" + cybergym_contract.body_hmac_hex(body, HMAC)
    cyb = cybergym_ingest.validate_report(
        payload, producer=PRODUCER, audience=("finney", 39), now=now
    )
    cyb = cybergym_ingest.bind_authenticated_body(cyb, body)
    cybergym_ingest.store_report(store, cyb, signature=signature)
    store.write(lambda c: c.execute(
        "CREATE TABLE IF NOT EXISTS cybergym_epoch_status(epoch INTEGER PRIMARY KEY, state TEXT NOT NULL)"))
    store.write(lambda c: c.execute(
        "INSERT OR REPLACE INTO cybergym_epoch_status(epoch, state) VALUES (?, ?)",
        (epoch, adapter.EPOCH_CLOSED)))

    # Registration snapshot: both lane owners plus the burn sink.
    for hotkey, uid in ((UID163, 163), (UID250, 250), (BURN, 204)):
        store.write(lambda c, hk=hotkey, u=uid: c.execute(
            "INSERT OR REPLACE INTO metagraph_hotkeys"
            "(network, netuid, hotkey, uid, coldkey, block, updated_at_iso) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", ("finney", 39, hk, u, "", 100, gen)))


def _compose(tmp_path, now: datetime) -> dict:
    store = Store(str(tmp_path / "v3.sqlite"), prefer_env_database_url=False)
    store.migrate()
    _seed(store, now)
    return weights.build_signed_vector(store, signing_key_hex="11" * 32, now=now)


def test_v3_compose_credits_the_cybergym_solver(monkeypatch, tmp_path):
    _apply_env(monkeypatch, validated_supply_enabled=True)
    vector = _compose(tmp_path, datetime.now(timezone.utc))

    supply = vector["policy_metadata"]["validated_supply"]
    assert supply["contract_version"] == "v3"
    assert supply["intel_tdx_allocation"] == 0.70
    assert supply["cybergym_allocation"] == 0.30
    assert vector["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(0.0)

    lane = vector["policy_metadata"]["cybergym_lane"]["weights"]
    # single-owner lane: the solver earns the whole 30%, keyed by its uid.
    assert pytest.approx(sum(float(v) for v in lane.values())) == 0.30
    assert any(str(uid) == "250" for uid in lane), lane


def test_missing_validated_supply_enabled_silently_falls_back(monkeypatch, tmp_path):
    """Without the enable flag the composer applies no contract at all — the
    exact silent fallback that broke every live v3 attempt."""
    _apply_env(monkeypatch, validated_supply_enabled=False)
    vector = _compose(tmp_path, datetime.now(timezone.utc))

    assert "validated_supply" not in vector["policy_metadata"]
    assert "cybergym_lane" not in vector["policy_metadata"]
