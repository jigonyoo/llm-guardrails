#!/usr/bin/env python3
"""Run a corpus written to BREAK this detector, and print what got through.

    python scripts/adversarial.py                 # default threshold
    python scripts/adversarial.py --threshold 1   # does tuning help?
    python scripts/adversarial.py --show          # print every miss, by name

data/inputs.jsonl was written by the same person who wrote the detector, so the
number it produces is a claim about that person's imagination. This file is the
other corpus: 42 attacks chosen from families the detector was never shown, and
8 benign lines a naive fix would start blocking.
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardrails.detect import scan_input                        # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=3)
    ap.add_argument("--show", action="store_true", help="print every miss")
    ap.add_argument("--data", default=os.path.join(HERE, "data",
                                                   "adversarial.jsonl"))
    a = ap.parse_args(argv)

    rows = load(a.data)
    attacks = [r for r in rows if r["label"] == "attack"]
    benign = [r for r in rows if r["label"] != "attack"]

    caught, missed = [], []
    for r in attacks:
        (caught if scan_input(r["text"], a.threshold).blocked else missed
         ).append(r)
    alarms = [r for r in benign if scan_input(r["text"], a.threshold).blocked]

    print(f"  threshold {a.threshold}")
    print(f"  attacks blocked      {len(caught)}/{len(attacks)}")
    print(f"  benign wrongly held  {len(alarms)}/{len(benign)}")

    by_family = collections.Counter(r.get("category", "?").split("/")[0]
                                    for r in missed)
    print("\n  what got through, by family")
    for fam, n in by_family.most_common():
        total = sum(1 for r in attacks
                    if r.get("category", "?").split("/")[0] == fam)
        print(f"    {fam:<14} {n} of {total}")

    zeros = sum(1 for r in missed if scan_input(r["text"], 99).score == 0)
    print(f"\n  misses that score exactly 0: {zeros} of {len(missed)}"
          f"   <- no threshold reaches these")

    if a.show:
        print("\n  every miss, verbatim:")
        for r in missed:
            print(f"    [{r.get('category','?'):<16}] "
                  f"{r['text'][:88].replace(chr(10), ' ')}")
    for r in alarms:
        print(f"\n  FALSE ALARM: {r['text'][:90]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
