"""The concrete HTTP client behind the validator's `RoundClient` seam.

:mod:`cybergym_round_runtime` talks to the backend through a three-method protocol so the round
loop can be tested with fakes. This is the production implementation of that protocol over the v2
round API, using only the standard library so the validator picks up no new dependency.

Two decisions worth stating, because both are about not fabricating a round:

* **Every failure raises.** A fetch that returns garbage, a 500, or a timeout must not read as "no
  submissions" or "no scores" — an empty field composes an all-burn board, so silently swallowing
  an error would burn a whole round's emission on a transport hiccup. The runtime catches these
  and skips, keeping the previous weights.
* **The rebuild proof is taken as the server sends it.** It is server-authoritative by design
  (a miner-supplied corpus would make every PoC "solve"), so the client neither fills in a
  default nor accepts a submission whose proof is missing.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Callable
from dataclasses import dataclass
from decimal import Decimal

from cathedral_thin.cybergym_round_eval import MinerRoundResult, Submission, TaskProof


class RoundClientError(RuntimeError):
    """The backend could not be reached or answered malformed. Always raised, never absorbed."""


#: (message_bytes) -> signature hex. Injected: the validator holds its own hotkey, and this
#: module must never see a seed. None means unsigned, which an enforcing backend refuses.
SignFn = Callable[[bytes], str]


def results_message(
    validator_hotkey: str, round_id: int, rows: Sequence[Mapping]
) -> bytes:
    """The canonical bytes the backend will verify. Must match `validator_auth.results_message`.

    Covers every verdict, not just the sender: signing only the hotkey would let anyone who saw
    one report replay its signature over different scores. Sorted, so the wire order of the rows
    cannot change what was signed.
    """
    items = sorted(
        [
            str(r["miner_hotkey"]),
            str(Decimal(str(r.get("score", 0)))),
            bool(r.get("evaluated", True)),
        ]
        for r in rows
    )
    return (
        "cybergym:v2:results:"
        + validator_hotkey
        + ":"
        + str(int(round_id))
        + ":"
        + json.dumps(items, separators=(",", ":"))
    ).encode("utf-8")


def weights_message(
    validator_hotkey: str, round_id: int, weights: Mapping[str, str], burn: str
) -> bytes:
    body = json.dumps(
        sorted((str(k), str(v)) for k, v in dict(weights).items()),
        separators=(",", ":"),
    )
    return (
        "cybergym:v2:weights:"
        + validator_hotkey
        + ":"
        + str(int(round_id))
        + ":"
        + body
        + ":"
        + str(burn)
    ).encode("utf-8")


@dataclass
class HttpRoundClient:
    """Talks the v2 round API. `base_url` points at the backend, e.g. http://host:8700"""

    base_url: str
    validator_hotkey: str
    timeout: float = 30.0
    #: Signs score reports with this validator's hotkey. Without it reports go unsigned, which an
    #: enforcing backend refuses -- deliberately, since an unsigned score is a score anyone could
    #: have sent.
    sign: SignFn | None = None

    def _url(self, path: str, **query) -> str:
        url = f"{self.base_url.rstrip('/')}{path}"
        return f"{url}?{urllib.parse.urlencode(query)}" if query else url

    def _request(self, path: str, *, payload: dict | None = None, **query) -> dict:
        url = self._url(path, **query)
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        req = urllib.request.Request(
            url, data=data, headers=headers, method="POST" if data else "GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            raise RoundClientError(f"{path} -> HTTP {exc.code}: {detail}") from exc
        except Exception as exc:
            raise RoundClientError(f"{path} -> {exc}") from exc
        if not isinstance(body, dict):
            raise RoundClientError(f"{path} -> expected a JSON object")
        return body

    # ------------------------------------------------------------------ the clock
    def fetch_round(self) -> dict:
        """Block height and round geometry. Off-chain this is the height everyone agrees on."""
        body = self._request("/v2/round")
        if "block" not in body:
            raise RoundClientError("/v2/round carried no block height")
        return body

    # ------------------------------------------------------------------ RoundClient protocol
    def fetch_round_tasks(self, round_id: int) -> Sequence[str]:
        body = self._request("/v2/tasks", round=round_id)
        tasks = body.get("tasks")
        if not isinstance(tasks, list) or not tasks:
            raise RoundClientError("/v2/tasks carried no task set")
        return [str(t) for t in tasks]

    def fetch_submissions(self, round_id: int) -> Sequence[Submission]:
        body = self._request("/v2/submissions", round=round_id)
        rows = body.get("submissions")
        if not isinstance(rows, list):
            raise RoundClientError("/v2/submissions carried no submission list")
        out: list[Submission] = []
        for row in rows:
            try:
                tasks = tuple(
                    TaskProof(
                        task_id=str(t["task_id"]),
                        poc=base64.b64decode(t["poc_b64"]),
                        proof=t["proof"],
                    )
                    for t in row.get("tasks", [])
                )
                out.append(
                    Submission(
                        miner_hotkey=str(row["miner_hotkey"]),
                        agent_digest=str(row.get("agent_digest", "")),
                        tasks=tasks,
                    )
                )
            except Exception as exc:
                raise RoundClientError(f"malformed submission row: {exc}") from exc
        return out

    def post_results(
        self, round_id: int, results: Mapping[str, MinerRoundResult]
    ) -> None:
        rows = [
            {
                "miner_hotkey": r.miner_hotkey,
                "score": str(r.score),
                "evaluated": r.evaluated,
                "solved": r.solved,
                "total": r.total,
            }
            for r in results.values()
        ]
        payload = {
            "validator_hotkey": self.validator_hotkey,
            "round_id": round_id,
            "results": rows,
        }
        if self.sign is not None:
            payload["signature"] = self.sign(
                results_message(self.validator_hotkey, round_id, rows)
            )
        self._request("/v2/results", payload=payload)

    def report_weights(
        self, round_id: int, weights: Mapping[str, Decimal], burn: Decimal
    ) -> bool:
        """Tell the backend what this validator composed, for the operator dashboard.

        DISPLAY ONLY: it feeds no score and no average, so a backend that ignores or mangles it
        cannot change a payout. Best-effort by design — it returns False instead of raising,
        because failing to report what we set must never stop us from setting it.
        """
        try:
            rows = {hk: str(w) for hk, w in weights.items()}
            payload = {
                "validator_hotkey": self.validator_hotkey,
                "round_id": round_id,
                "weights": rows,
                "burn": str(burn),
            }
            if self.sign is not None:
                payload["signature"] = self.sign(
                    weights_message(self.validator_hotkey, round_id, rows, str(burn))
                )
            self._request("/v2/weights", payload=payload)
            return True
        except RoundClientError:
            return False

    def fetch_average_scores(self, round_id: int) -> Mapping[str, Decimal]:
        body = self._request("/v2/average", round=round_id)
        scores = body.get("scores")
        if not isinstance(scores, dict):
            raise RoundClientError("/v2/average carried no scores")
        try:
            return {str(hk): Decimal(str(v)) for hk, v in scores.items()}
        except Exception as exc:
            raise RoundClientError(f"malformed average score: {exc}") from exc


__all__ = ["RoundClientError", "HttpRoundClient"]
