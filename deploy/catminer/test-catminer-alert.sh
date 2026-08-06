#!/bin/bash
# Exercises every rule in cathedral-catminer-alert-check, including the ones
# that must NOT alert. A canary is only worth its exit code if both directions
# are pinned: an alert that never clears is as useless as one that never fires.
set -u
export LC_ALL=C
CHECK="${CHECK:-./cathedral-catminer-alert-check}"
ASSERT="${ASSERT:-./cathedral-catminer-assert}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

ts() { date -u -d "-$1 seconds" "+%Y-%m-%dT%H:%M:%S.000Z"; }

# Rule 2 consults systemd, so every journal case names a unit that is genuinely
# active on this host; otherwise rule 2 would alert first and each case below
# would pass for the wrong reason. LIVE_UNIT is resolved, not assumed.
LIVE_UNIT="${CATMINER_TEST_LIVE_UNIT:-}"
if [ -z "$LIVE_UNIT" ]; then
  for candidate in cathedral-catminer-worker.service ssh.service systemd-journald.service; do
    if systemctl is-active --quiet -- "$candidate" 2>/dev/null; then LIVE_UNIT="$candidate"; break; fi
  done
fi
[ -n "$LIVE_UNIT" ] || { echo "no active unit found to stand in for the miner; set CATMINER_TEST_LIVE_UNIT"; exit 2; }
echo "using '$LIVE_UNIT' as the stand-in active miner unit"

run() { CATMINER_JOURNAL="$1" CATMINER_EPOCH_SECS="${3:-1500}" CATMINER_UNIT="$LIVE_UNIT" "$CHECK" >/dev/null 2>&1; echo $?; }

expect() { # name journal want_rc [epoch_secs]
  local got; got=$(run "$2" "" "${4:-1500}")
  if [ "$got" = "$3" ]; then PASS=$((PASS+1)); printf 'ok    %s\n' "$1"
  else FAIL=$((FAIL+1)); printf 'FAIL  %s (want rc=%s got rc=%s)\n' "$1" "$3" "$got"; fi
}

green() { printf '{"ts":"%s","event":"EPOCH_STATUS","verdict":"GREEN","epoch":%s,"earned":3.5,"receipt_verified":true,"gates":{"attestation":"ok"},"lane":{}}\n' "$(ts "$1")" "${2:-1}"; }
red()   { printf '{"ts":"%s","event":"EPOCH_STATUS","verdict":"RED","epoch":%s,"reason":"earned_zero"}\n' "$(ts "$1")" "${2:-1}"; }
start() { printf '{"ts":"%s","event":"MINER_STARTUP","miner":"5Ref"}\n' "$(ts "$1")"; }

# Rule 1 — blindness is an alert, in every shape.
expect "rule1 missing journal alerts"      "$TMP/nope.jsonl" 1
: > "$TMP/empty.jsonl"
expect "rule1 empty journal alerts"        "$TMP/empty.jsonl" 1
mkdir -p "$TMP/dir.jsonl"
expect "rule1 non-regular file alerts"     "$TMP/dir.jsonl" 1
printf 'not json at all\n' > "$TMP/garbage.jsonl"
expect "rule1 unparseable journal alerts"  "$TMP/garbage.jsonl" 1

# Rule 2 — the miner unit itself. This is the acceptance criterion "kill the
# miner mid-epoch, alert fires": a journal that is otherwise perfectly healthy
# must still alert when the unit is not running.
{ start 20000; green 600 9; } > "$TMP/unitdead.jsonl"
got=$(CATMINER_JOURNAL="$TMP/unitdead.jsonl" CATMINER_UNIT="cathedral-catminer-definitely-not-installed.service" "$CHECK" >/dev/null 2>&1; echo $?)
if [ "$got" = "1" ]; then PASS=$((PASS+1)); printf 'ok    rule2 dead miner unit alerts on a healthy journal\n'
else FAIL=$((FAIL+1)); printf 'FAIL  rule2 dead miner unit alerts on a healthy journal (want rc=1 got rc=%s)\n' "$got"; fi

# Rule 3 — stale journal.
green 100000 7 > "$TMP/stale.jsonl"
expect "rule3 stale journal alerts"        "$TMP/stale.jsonl" 1

# Rule 4 — no completed epoch, and the crash-loop grace it must not grant.
{ start 60; } > "$TMP/warming.jsonl"
expect "rule4 fresh startup does not alert" "$TMP/warming.jsonl" 0
{ start 100000; start 90000; start 60; } > "$TMP/crashloop.jsonl"
expect "rule4 crash loop cannot renew its own grace" "$TMP/crashloop.jsonl" 1

# Rule 5 — a recent RED alerts; an old RED alone does not.
{ start 9000; green 7000 5; red 600 6; } > "$TMP/red.jsonl"
expect "rule5 recent RED alerts"           "$TMP/red.jsonl" 1
{ start 20000; red 7000 4; green 600 5; } > "$TMP/recovered.jsonl"
expect "rule5 old RED followed by GREEN clears" "$TMP/recovered.jsonl" 0

# Rule 6 — two consecutive REDs inside 90m with no GREEN since.
{ start 20000; green 5000 3; red 3000 4; red 2400 5; } > "$TMP/streak.jsonl"
expect "rule6 two consecutive REDs alert"  "$TMP/streak.jsonl" 1

# The happy path must be silent, or the alert is noise.
{ start 20000; green 3000 8; green 600 9; } > "$TMP/happy.jsonl"
expect "healthy loop does not alert"       "$TMP/happy.jsonl" 0

# Rotation: the live journal is empty right after a copytruncate, and the
# rotated generation is what keeps recent history visible.
: > "$TMP/rot.jsonl"; { start 20000; green 600 9; } > "$TMP/rot.jsonl.1"
expect "rotated generation keeps the check sighted" "$TMP/rot.jsonl" 0

# --- assert script: the producer side of the same contract ---
areun() { CATMINER_JOURNAL="$1" CATMINER_MINER_HOTKEY=5Ref CATMINER_ORACLE_CMD="$2" \
  CATMINER_EXPECTED_GATES="${3:-attestation=ok}" "$ASSERT" >/dev/null 2>&1; echo $?; }
aexpect() { local got; got=$(areun "$2" "$3" "${5:-attestation=ok}")
  if [ "$got" = "$4" ]; then PASS=$((PASS+1)); printf 'ok    %s\n' "$1"
  else FAIL=$((FAIL+1)); printf 'FAIL  %s (want rc=%s got rc=%s)\n' "$1" "$4" "$got"; fi
}

OK='{"epoch":9,"earned":3.5,"receipt_verified":true,"gates":{"attestation":"ok"},"lane":{"cybergym":0.3}}'
aexpect "assert GREEN on a clean epoch"     "$TMP/a1.jsonl" "echo '$OK'" 0
aexpect "assert RED when oracle fails"      "$TMP/a2.jsonl" "exit 3" 1
aexpect "assert RED when oracle is silent"  "$TMP/a3.jsonl" "true" 1
aexpect "assert RED on unparseable oracle"  "$TMP/a4.jsonl" "echo 'nonsense'" 1
aexpect "assert RED when earned is zero"    "$TMP/a5.jsonl" "echo '{\"epoch\":9,\"earned\":0,\"receipt_verified\":true,\"gates\":{\"attestation\":\"ok\"}}'" 1
aexpect "assert RED when a gate disagrees"  "$TMP/a6.jsonl" "echo '{\"epoch\":9,\"earned\":1,\"receipt_verified\":true,\"gates\":{\"attestation\":\"absent\"}}'" 1
aexpect "assert RED when a gate vanished"   "$TMP/a7.jsonl" "echo '{\"epoch\":9,\"earned\":1,\"receipt_verified\":true,\"gates\":{}}'" 1
aexpect "assert RED when receipt unverified" "$TMP/a8.jsonl" "echo '{\"epoch\":9,\"earned\":1,\"receipt_verified\":false,\"gates\":{\"attestation\":\"ok\"}}'" 1

# A RED written by the assert must be visible to the alert: producer and
# consumer agree on the schema, which is the seam most likely to rot.
if [ "$(run "$TMP/a5.jsonl")" = "1" ]; then PASS=$((PASS+1)); printf 'ok    assert RED is seen by the alert\n'
else FAIL=$((FAIL+1)); printf 'FAIL  assert RED is seen by the alert\n'; fi
if [ "$(run "$TMP/a1.jsonl")" = "0" ]; then PASS=$((PASS+1)); printf 'ok    assert GREEN is accepted by the alert\n'
else FAIL=$((FAIL+1)); printf 'FAIL  assert GREEN is accepted by the alert\n'; fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
