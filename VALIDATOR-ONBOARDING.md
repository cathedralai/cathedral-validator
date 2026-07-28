# Run a Cathedral SN39 validator (thin mode)

One page. You follow Cathedral's signed score feed; your validator verifies it
cryptographically before every write and refuses anything it cannot prove.

## What you need

- A Bittensor wallet registered on SN39 with a validator permit and stake
- Python 3.11+, a machine that stays on
- This repository at current `main`

## Install and run

```bash
git clone <repo-url> cathedral-validator && cd cathedral-validator
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m scaffold.cli serve \
  --config config/validator.toml \
  --wallet-name <your-wallet> --wallet-hotkey <your-hotkey>
```

That is a **dry run**: it fetches, verifies, and prints what it *would* write,
touching nothing on chain. Watch a few ticks. When the output looks right,
add `--broadcast`.

## What it verifies before every write

- The feed is signed by Cathedral's published key (pinned in the default
  config; check it against `https://api.cathedral.computer/.well-known/cathedral-jwks.json`)
- Fresh, unexpired, and newer than anything it applied before (replay-fenced)
- The exact `validated_supply_v1` contract: 90% attested compute / 10% burn,
  burn destination equal to the live subnet owner
- Target UIDs provably stable for the write's whole lifetime

If any check fails, it writes nothing and prints one line saying why.

## What it never does

- Never takes the burn destination from the feed on faith
- Never writes twice for the same attempt (durable attempt journal)
- Never guesses: an unprovable outcome halts, restarts, and re-proves the
  exact transaction rather than resubmitting

## Reading the log

```
   chain     block 8717865 · epoch in 65m · last write 25m ago
   feed      v…638983 · signed · fresh · fence ok
   weights   163 90.0% · 204 10.0% burn
   submit    0x6653be08…de8c8 · block 8715784 · finalized
   ✓ weights written · in 41s
```

`✗ waiting out the chain's write cooldown` is the chain's own once-per-20-min
rule, not an error. The validator runs continuously and paces itself.

## Questions

Contact Fred. The full-provenance mode (independent recomputation from raw
TDX evidence) exists for operators with evidence access; thin is the intended
mode for everyone else and carries every verification listed above.
