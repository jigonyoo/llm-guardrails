"""The README prints a number this detector does badly on: 5 of 42.

A number in a README goes stale silently. These tests make it fail loudly
instead -- if the detector improves (or regresses), CI breaks here and whoever
changed it has to go update the README section that quotes this output.

Nothing here asserts the detector is good. It asserts the published number is
still true.
"""
import json
import os

import pytest

from guardrails.detect import scan_input

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "..", "data", "adversarial.jsonl")


def load():
    with open(CORPUS, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


ROWS = load()
ATTACKS = [r for r in ROWS if r["label"] == "attack"]
BENIGN = [r for r in ROWS if r["label"] != "attack"]


def blocked_at(threshold):
    return sum(1 for r in ATTACKS if scan_input(r["text"], threshold).blocked)


def test_corpus_shape_is_42_attacks_and_8_benign():
    assert (len(ATTACKS), len(BENIGN)) == (42, 8)


def test_every_row_has_a_family_label():
    # the README's per-family table is generated from this field
    for r in ROWS:
        assert r.get("category"), r


def test_the_published_number_is_still_five_of_fortytwo():
    assert blocked_at(3) == 5


def test_no_false_alarms_on_the_benign_near_misses():
    assert [r for r in BENIGN if scan_input(r["text"], 3).blocked] == []


@pytest.mark.parametrize("threshold,expected", [(1, 6), (2, 6), (3, 5), (4, 0)])
def test_threshold_sweep_matches_the_readme_table(threshold, expected):
    assert blocked_at(threshold) == expected


def test_thirtysix_of_the_misses_score_exactly_zero():
    # this is the claim that tuning cannot rescue the detector: a score of 0
    # is not reachable by any threshold >= 1
    missed = [r for r in ATTACKS if not scan_input(r["text"], 3).blocked]
    zeros = [r for r in missed if scan_input(r["text"], 99).score == 0]
    assert (len(zeros), len(missed)) == (36, 37)


def test_every_non_latin_attack_gets_through():
    # the README says 8 of 8. If someone adds unicode normalisation this fails,
    # which is the point.
    nl = [r for r in ATTACKS if r.get("category", "").startswith("non-latin")]
    assert len(nl) == 8
    assert all(not scan_input(r["text"], 3).blocked for r in nl)


def test_all_thirteen_signals_are_ascii():
    # the README explains the non-latin result by this fact
    from guardrails.patterns import INJECTION_SIGNALS
    assert len(INJECTION_SIGNALS) == 13
    for sig in INJECTION_SIGNALS:
        assert all(ord(c) < 128 for c in str(sig)), sig
