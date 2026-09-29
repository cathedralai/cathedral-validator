"""The two copies of the KING payout curve in this repo must agree.

There are three copies of the payout curve: distill's, the publisher's vendored copy
(`scaffold/publisher/cybergym_tournament.py`), and the validator's own
`cathedral_thin/cybergym_round_scoring.py`. `test_vendored_award_shares_matches_distill` guards
the first edge. Nothing compared the two copies in THIS repo to each other: the validator composes
its local board with one and the publisher pays with the other, so a deliberate curve change that
updated one copy (and its literal pins in `test_cybergym_round_scoring.py`) and missed the other
would have the recorded board disagree with the actual payout, and neither side would look wrong.
(That is how the KING curve itself drifted for six days in September, caught in #239.)

Both modules import only the standard library, so they are imported plainly. A skip here could
only mean one of them was moved or renamed, which is exactly when this guard has to fail.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_thin import cybergym_round_scoring as local  # noqa: E402
from scaffold.publisher import cybergym_tournament as vendored  # noqa: E402


class TestTheTwoCurvesInThisRepoAgree:
    def test_the_share_schedules_are_identical(self):
        # String forms, not Decimal equality: Decimal("0.93") == Decimal("0.9300"), so comparing
        # values would miss a quantization drift between the copies.
        for n in range(0, 8):
            assert [str(x) for x in local.award_shares(n)] == [
                str(x) for x in vendored._award_shares(n)
            ], f"n={n}"

    def test_the_runner_up_constants_are_identical(self):
        assert local.RUNNER_UP_SHARES == vendored.RUNNER_UP_SHARES
        assert local.WINNER_SLOTS == vendored.WINNER_SLOTS
