"""Live runner for `independent_v1`: rent, list, collect, compose, canary.

This package is deliberately NOT `cathedral_thin.independent`. The composer
package has an import-graph ban on ``bittensor``, ``ssl`` at import time, and
any chain client. The live path lives here so those bans stay meaningful.

What this package is allowed to do:

* talk to ``https://cathedral.computer/v1`` with a customer API key, to rent
  and list Intel TDX Workers;
* dial a miner ``POST /v1/evidence`` over public HTTPS and observe the TLS
  SPKI so collect can bind the channel;
* read the SN39 metagraph and, through an injected canary transport, submit
  ``set_mechanism_weights`` as the dedicated canary hotkey.

What it must never do:

* import or run as the live relay hotkey or the burn destination;
* pass ``--broadcast`` on the thin relay launcher;
* bind Compute mass from a mock QVL or from attestation without re-derived
  work units;
* share the thin validator journal.
"""

from __future__ import annotations
