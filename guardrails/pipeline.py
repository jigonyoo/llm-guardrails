"""A tiny request/response flow so the before/after is apples-to-apples.

`Guard(mode="naive")`  passes everything through untouched — this is the
"no guardrails" baseline almost every first-cut LLM app ships with.

`Guard(mode="guarded")` runs scan_input before the model and scan_output
after it. The model itself is stubbed (offline, deterministic) so the demo
runs with no key: we only care what the *guard* does, not what the model says.
"""

from dataclasses import dataclass
from typing import Optional

from .detect import scan_input, scan_output, InputVerdict, OutputVerdict


@dataclass
class Result:
    allowed: bool                       # did the request reach the model?
    input_verdict: Optional[InputVerdict]
    output_verdict: Optional[OutputVerdict]
    delivered: str                      # what the end user finally sees


class Guard:
    def __init__(self, mode: str = "guarded", threshold: int = 3):
        assert mode in ("naive", "guarded")
        self.mode = mode
        self.threshold = threshold

    def handle(self, user_input: str, model_output: str) -> Result:
        """Run one turn. `model_output` is the (stubbed) completion the model
        would produce for this input — supplied by the harness so everything
        stays offline and deterministic."""
        if self.mode == "naive":
            # No checks anywhere: injection reaches the model, leaks reach the user.
            return Result(True, None, None, model_output)

        iv = scan_input(user_input, self.threshold)
        if iv.blocked:
            # Refuse before the model / any tool is ever touched.
            return Result(False, iv, None,
                          "⛔ Request blocked by input guard "
                          f"({', '.join(iv.reasons)}).")

        ov = scan_output(model_output)
        return Result(True, iv, ov, ov.safe_text)
