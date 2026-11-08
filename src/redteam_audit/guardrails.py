"""Output guardrail (configuration C): screen each reply before the customer sees it.

Deterministic and model-free, so it adds no API cost or latency worth measuring. If any detector fires,
the reply is replaced with a safe handoff message and the reason is logged.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .detectors import detect
from .target import BotResult

FALLBACK = "Sorry, I can't help with that here. I can connect you with a human agent who can take a look."


@dataclass
class Guarded:
    result: BotResult
    blocked_by: list[str]


def guard(result: BotResult) -> Guarded:
    findings = detect(result.reply)
    if not findings:
        return Guarded(result, [])
    return Guarded(replace(result, reply=FALLBACK, action="handoff", citations=[]), sorted(findings))
