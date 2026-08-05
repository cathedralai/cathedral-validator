"""The producer side of the pin<->lane cross-check."""
from scaffold import validator_thin as vt


def _payload(contract_version):
    return {
        "policy_metadata": {
            "validated_supply": {
                "contract_version": contract_version,
                "intel_tdx_allocation": 0.70,
                "cybergym_allocation": 0.30,
                "fixed_burn_allocation": 0.0,
                "burn_hotkey": "5G3qVaXzKMPDm5AJ3dpzbpUC27kpccBvDwzSWXrq8M6qMmbC",
            }
        }
    }


def test_a_v3_payload_stamps_the_v3_contract():
    assert vt._dry_run_contract_version(_payload("v3")) == "validated_supply_v3"


def test_a_v2_payload_stamps_nothing():
    assert vt._dry_run_contract_version(_payload("v2")) is None


def test_no_supply_block_stamps_nothing():
    assert vt._dry_run_contract_version({"policy_metadata": {}}) is None
    assert vt._dry_run_contract_version({}) is None
