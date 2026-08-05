"""The operator-facing stream is presentation only, and must stay harmless.

Two properties matter more than layout. Nothing rendered may carry a terminal
escape from upstream data, because lifecycle details include chain-supplied and
publisher-supplied strings. And rendering must never be able to break a tick:
a formatting bug should degrade to an ugly line, never raise into the loop.

Colour is asserted off, because the suite runs without a tty; that is also what
makes the output assertions here stable.
"""

from __future__ import annotations

from scaffold import render


def _out(capsys) -> str:
    return capsys.readouterr().out


def _emit(event: str, detail: str = "") -> None:
    render.lifecycle(event, detail, "2026-07-27T22:04:17.239Z")


# -- safety -----------------------------------------------------------------


def test_no_ansi_escapes_when_stdout_is_not_a_tty(capsys):
    _emit("VECTOR accepted", "miners=1 burn=10.0%")
    assert "\033[" not in _out(capsys)


def test_control_characters_in_detail_are_neutralized(capsys):
    # A publisher-controlled string must not be able to repaint the terminal,
    # clear the screen, or forge a line that looks like a different event.
    _emit("VECTOR accepted", "miners=\033[31mEVIL\007 burn=1%")
    out = _out(capsys)
    assert "\033" not in out
    assert "\007" not in out


def test_control_characters_in_an_unknown_event_are_neutralized(capsys):
    _emit("TOTALLY NEW EVENT", "detail=\033[2Jwiped")
    out = _out(capsys)
    assert "\033" not in out


# -- resilience -------------------------------------------------------------


def test_an_unknown_event_still_reaches_the_operator(capsys):
    # A new call site must never vanish silently just because the renderer has
    # no entry for it.
    _emit("BRAND NEW", "thing=42")
    assert "42" in _out(capsys)


def test_a_renderer_failure_degrades_instead_of_raising(capsys, monkeypatch):
    def explode(*_a, **_k):
        raise RuntimeError("formatting blew up")

    monkeypatch.setitem(render._RENDERERS, "MAP complete", explode)
    _emit("MAP complete", "vector=163:0.9")  # must not raise
    assert "MAP complete" in _out(capsys)


def test_malformed_weight_values_do_not_raise(capsys):
    _emit("MAP complete", "burn_uid=204 vector=163:notanumber,204:0.1")
    assert "163" in _out(capsys)


# -- reading ----------------------------------------------------------------


def test_weights_render_as_percentages_with_the_burn_leg_labelled(capsys):
    _emit("MAP complete", "uids=2 burn_uid=204 vector=163:0.900000,204:0.100000")
    out = _out(capsys)
    assert "90.0%" in out
    assert "10.0%" in out
    assert "burn" in out


def test_a_value_the_writer_meant_to_hold_spaces_tokenizes_whole():
    # Call sites interpolate Python containers and reprs. A tokenizer that
    # stops at the first interior space truncates the value AND hands the tail
    # to whatever renders leftover.
    kv, leftover = render.parse_detail(
        "uids=2 wire_uids=[0, 1] wire_weights=[58982, 7282] vector=0=0.9,1=0.1"
    )
    assert kv["wire_uids"] == "[0, 1]"
    assert kv["wire_weights"] == "[58982, 7282]"
    assert kv["uids"] == "2"
    assert leftover == ""

    kv, leftover = render.parse_detail("error='package digest not pinned; refusing'")
    assert kv["error"] == "package digest not pinned; refusing"
    assert leftover == ""


def test_the_dry_run_line_never_prints_list_repr_debris(capsys):
    # The exact detail the quickstart produces. Its last line used to end
    # "dry run, nothing written 1]  7282]" -- the tails of the two list
    # literals -- which is the first thing a new operator ever reads.
    _emit(
        "WEIGHTS dry-run",
        "uids=2 wire_uids=[0, 1] wire_weights=[58982, 7282] vector=0=0.9000,1=0.1000",
    )
    out = _out(capsys)
    assert "dry run, nothing written" in out
    assert "2 uids" in out
    assert "]" not in out
    assert "7282" not in out


def test_the_dry_run_line_renders_named_fields_only(capsys):
    # Widening the tokenizer is not the guarantee; refusing to print anything
    # unnamed is. A detail shape no future parser handles must still not put
    # fragments on the operator's screen.
    _emit("WEIGHTS dry-run", "uids=2 wire_uids=(0, 1) junk fragment]")
    out = _out(capsys)
    assert "2 uids" in out
    assert "junk" not in out
    assert "fragment" not in out


def test_the_dry_run_line_names_the_burn_leg_and_vector_when_present(capsys):
    _emit(
        "WEIGHTS dry-run",
        "uids=2 burn_uid=204 burn_share=0.100000 vector_id=08abd7f7-e6b5",
    )
    out = _out(capsys)
    assert "burn uid 204" in out
    assert "10.0%" in out
    assert "08abd7f7" in out


def test_the_dry_run_line_neutralizes_what_it_does_render(capsys):
    _emit("WEIGHTS dry-run", "uids=\033[31m2 burn_uid=\033[2J204")
    out = _out(capsys)
    assert "\033" not in out


def test_block_deltas_render_as_durations(capsys):
    # 259 blocks is not a quantity anyone reasons about; ~52 minutes is.
    _emit("PREFLIGHT complete", "block=8716129 blocks_until_epoch=259")
    assert "52m" in _out(capsys)


def test_known_refusals_get_a_plain_reading_that_keeps_the_original():
    plain, original = render.humanize(
        "VectorError: submission is inside the live validator weight-update cooldown"
    )
    assert "cooldown" in plain
    assert plain != original
    # The precise message is still available; the plain reading adds to it.
    assert "VectorError" in original


def test_an_unknown_error_passes_through_unchanged():
    plain, original = render.humanize("VectorError: something nobody mapped")
    assert plain == "VectorError: something nobody mapped"
    assert original == ""


def test_humanize_neutralizes_before_matching():
    plain, _ = render.humanize("\033[31mVectorError: mystery")
    assert "\033" not in plain
