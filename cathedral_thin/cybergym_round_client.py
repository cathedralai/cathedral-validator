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
from dataclasses import dataclass
from decimal import Decimal

from cathedral_thin.cybergym_round_eval import MinerRoundResult, Submission, TaskProof


class RoundClientError(RuntimeError):
    """The backend could not be reached or answered malformed. Always raised, never absorbed."""


@dataclass
class HttpRoundClient:
    """Talks the v2 round API. `base_url` points at the backend, e.g. http://host:8700"""

    base_url: str
    validator_hotkey: str
    timeout: float = 30.0

    def _url(self, path: str, **query) -> str:
        url = f"{self.base_url.rstrip('/')}{path}"
        return f"{url}?{urllib.parse.urlencode(query)}" if query else url

    def _request(self, path: str, *, payload: dict | None = None, **query) -> dict:
        url = self._url(path, **query)
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST" if data else "GET")
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
                    TaskProof(task_id=str(t["task_id"]),
                              poc=base64.b64decode(t["poc_b64"]),
                              proof=t["proof"])
                    for t in row.get("tasks", []))
                out.append(Submission(miner_hotkey=str(row["miner_hotkey"]),
                                      agent_digest=str(row.get("agent_digest", "")),
                                      tasks=tasks))
            except Exception as exc:
                raise RoundClientError(f"malformed submission row: {exc}") from exc
        return out

    def post_results(self, round_id: int, results: Mapping[str, MinerRoundResult]) -> None:
        payload = {
            "validator_hotkey": self.validator_hotkey,
            "round_id": round_id,
            "results": [
                {"miner_hotkey": r.miner_hotkey, "score": str(r.score),
                 "evaluated": r.evaluated, "solved": r.solved, "total": r.total}
                for r in results.values()
            ],
        }
        self._request("/v2/results", payload=payload)

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
