"""Deterministic signal tables for the guardrail layer.

Everything here is offline and rule-based — no LLM call, no network, no key.
Signals are *weighted* so a single suspicious word in an otherwise benign
sentence does not trip the gate; only a combination that looks like a real
attempt to override, exfiltrate, or jailbreak crosses the threshold.

Weights and the threshold are the two knobs you tune against your own traffic.
"""

import re

# --- Input side: prompt-injection / jailbreak signals (OWASP LLM01) ----------
# Each entry: (name, compiled_regex, weight). Weight >= STRONG on its own is
# almost never benign; weak signals only matter when they stack.

STRONG = 3
MED = 2
WEAK = 1

INJECTION_SIGNALS = [
    # Direct instruction override — the canonical injection opener.
    ("ignore_previous",
     re.compile(r"\b(ignore|disregard|forget|discard)\b[^.\n]{0,40}\b(previous|above|prior|earlier|all)\b[^.\n]{0,20}\b(instruction|prompt|rule|direction|context|message)s?\b", re.I),
     STRONG),
    # "you are now X with no rules" style role reset.
    ("role_reset",
     re.compile(r"\b(you\s+are\s+now|from\s+now\s+on|pretend\s+(to\s+be|you\s+are)|act\s+as)\b[^\n]{0,60}\b(no\s+(restrictions?|rules?|filters?|limits?)|unfiltered|uncensored|jailbroken|developer\s+mode|do\s+anything)\b", re.I),
     STRONG),
    # Named jailbreak personas.
    ("named_jailbreak",
     re.compile(r"\b(DAN|STAN|do\s+anything\s+now|dev(eloper)?\s+mode\s+enabled|god\s*mode)\b", re.I),
     MED),
    # System-prompt / instruction exfiltration.
    ("exfil_system_prompt",
     re.compile(r"\b(print|repeat|reveal|show|output|display|tell\s+me|what\s+(are|were)|spit\s+out)\b[^\n]{0,45}\b(system\s+prompt|hidden\s+prompt|your\s+(instruction|prompt|rules|hidden)|the\s+(text|words)\s+above|initial\s+prompt|instruction[s]?\s+(you\s+were\s+given|above|verbatim)|everything\s+(above|verbatim)?)\b", re.I),
     STRONG),
    # Secret/credential exfiltration.
    ("exfil_secret",
     re.compile(r"\b(print|reveal|show|send|leak|encode|base64|exfiltrate|email|post|upload)\b[^\n]{0,45}\b(api[\s_-]?keys?|secrets?|passwords?|tokens?|credentials?|environment\s+variables?|env\s+vars?|\.env)\b", re.I),
     STRONG),
    # Tool / command injection aimed at a downstream tool call.
    ("tool_injection",
     re.compile(r"\b(when\s+you\s+(call|use|run)|next\s+time\s+you|in\s+your\s+(tool|function)\s+call)\b[^.\n]{0,60}\b(run|exec|curl|wget|rm\s+-rf|drop\s+table|delete\s+from|;\s*shutdown)\b", re.I),
     STRONG),
    # Delimiter / format escape — pretending the user input has ended.
    ("delimiter_escape",
     re.compile(r"(```|\"\"\"|---|\[/?(INST|SYS|SYSTEM)\]|<\|?(system|im_start|im_end)\|?>)[^\n]{0,20}\b(system|assistant|new\s+instruction|actual\s+task)\b", re.I),
     MED),
    # Encoding smuggling: "decode this and follow it".
    ("encoded_payload",
     re.compile(r"\b(decode|base64|rot13|hex|from\s+base64)\b[^.\n]{0,40}\b(and|then)\b[^.\n]{0,30}\b(follow|execute|run|do\s+(it|what|as)|obey|comply)\b", re.I),
     STRONG),
    # Indirect injection markers hidden in retrieved / pasted content.
    ("indirect_marker",
     re.compile(r"(<!--|/\*|#\s*)?\s*(assistant|ai|system)\s*:\s*(forward|send|ignore|delete|reply|email|leak|exfiltrate)\b", re.I),
     STRONG),
    # Authority spoofing.
    ("authority_spoof",
     re.compile(r"\b(as\s+(an?\s+)?(admin|administrator|developer|openai|anthropic|system)|i\s+am\s+(your|the)\s+(developer|creator|admin))\b[^\n]{0,45}\b(override|allow|permit|unlock|bypass|disable)\b", re.I),
     STRONG),
]

# Phrases that, when the risky text is only *mentioned* (quoted, translated,
# summarized, defined), signal a benign meta-reference rather than an attack.
META_REFERENCE = re.compile(
    r"\b(translate|summariz|explain|what\s+does|meaning\s+of|define|paraphrase|proofread|correct|rewrite|detect|classify|example\s+of)\b"
    r"|is\s+this[^\n]{0,30}(prompt\s+injection|an?\s+attack|malicious|safe|jailbreak)",
    re.I,
)

# --- Output side: sensitive-info / secret leakage (OWASP LLM02 / LLM06) ------
# (name, regex, replacement-tag, needs_luhn)
SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]", False),
    ("aws_secret_key", re.compile(r"(?i)\baws_secret_access_key\b\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"), "aws_secret_access_key=[REDACTED]", False),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "[REDACTED_OPENAI_KEY]", False),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), "[REDACTED_GITHUB_TOKEN]", False),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]", False),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]", False),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]", False),
    ("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "[REDACTED_SSN]", False),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]", False),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[REDACTED_CC]", True),
]


def luhn_ok(digits: str) -> bool:
    """Luhn checksum — used to avoid flagging every 13-16 digit run as a card."""
    ds = [int(c) for c in digits if c.isdigit()]
    if not (13 <= len(ds) <= 16):
        return False
    total, alt = 0, False
    for d in reversed(ds):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0
