"""The guard engine: scan an inbound prompt, scan an outbound completion.

Two public entry points:
  * scan_input(text, threshold)  -> InputVerdict   (block prompt injection / jailbreak)
  * scan_output(text)            -> OutputVerdict  (redact leaked secrets / PII)

Both are pure functions over the signal tables in patterns.py. No LLM, no I/O.
"""

from dataclasses import dataclass, field
from typing import List, Tuple

from . import patterns as P


@dataclass
class InputVerdict:
    blocked: bool
    score: int
    threshold: int
    signals: List[Tuple[str, int]] = field(default_factory=list)
    meta_reference: bool = False

    @property
    def reasons(self) -> List[str]:
        return [name for name, _ in self.signals]


@dataclass
class OutputVerdict:
    leaked: bool
    findings: List[str]          # kinds of secret found, e.g. ["us_ssn", "email"]
    safe_text: str               # text with every secret redacted


def scan_input(text: str, threshold: int = 3) -> InputVerdict:
    """Score an inbound prompt against the injection signals.

    A benign *mention* of an attack phrase (translate / summarize / "is this a
    prompt injection?") downweights the strongest signals so we do not block
    people who are merely talking about injections.
    """
    hits: List[Tuple[str, int]] = []
    for name, rx, weight in P.INJECTION_SIGNALS:
        if rx.search(text):
            hits.append((name, weight))

    meta = bool(P.META_REFERENCE.search(text))
    score = sum(w for _, w in hits)

    if meta and hits:
        # Reference, not use: knock the score down by the single largest signal.
        # A real attack usually stacks signals, so it still crosses; a lone
        # quoted phrase inside "translate ..." falls back under threshold.
        score -= max(w for _, w in hits)

    return InputVerdict(
        blocked=score >= threshold,
        score=score,
        threshold=threshold,
        signals=hits,
        meta_reference=meta,
    )


def scan_output(text: str) -> OutputVerdict:
    """Redact secrets / PII from an outbound completion.

    Credit-card candidates are Luhn-checked so ordinary long digit runs
    (order numbers, timestamps) are not mangled.
    """
    findings: List[str] = []
    safe = text

    for name, rx, tag, needs_luhn in P.SECRET_PATTERNS:
        def _sub(m, _name=name, _tag=tag, _luhn=needs_luhn):
            whole = m.group(0)
            if _luhn and not P.luhn_ok(whole):
                return whole  # not a real card number — leave it alone
            if _name not in findings:
                findings.append(_name)
            # keep the field prefix for aws_secret_key (group-based tag)
            return _tag
        safe = rx.sub(_sub, safe)

    return OutputVerdict(leaked=bool(findings), findings=findings, safe_text=safe)
