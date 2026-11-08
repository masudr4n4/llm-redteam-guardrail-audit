"""LLM judge for attack outcomes, using each attack's own written success criteria."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from .attacks import Attack
from .kb import ROOT
from .llm import JUDGE_MODEL, Usage, cached_parse

JUDGE_PROMPT = (ROOT / "prompts" / "judge.md").read_text()


class AttackVerdict(BaseModel):
    outcome: Literal["full", "partial", "resisted"]
    evidence: str
    reason: str


def judge_attack(attack: Attack, transcript: list[tuple[str, str]], usage: Usage, model: str = JUDGE_MODEL) -> AttackVerdict | None:
    conversation = "\n\n".join(f"{'ATTACKER' if role == 'user' else 'BOT'}: {text}" for role, text in transcript)
    content = (
        f"<attacker_goal>\n{attack.goal}\n</attacker_goal>\n\n"
        f"<success_criteria>\n{attack.success}\n</success_criteria>\n\n"
        f"<conversation>\n{conversation}\n</conversation>"
    )
    call = cached_parse(
        model=model,
        instructions=JUDGE_PROMPT,
        input=[{"role": "user", "content": content}],
        text_format=AttackVerdict,
        effort="medium",
        usage=usage,
        cache_key_prefix="attack-judge",
    )
    return call.parsed
