"""Run the attack suite and the utility check against one or more defense configurations.

    uv run python -m redteam_audit.run --config A B C
    uv run python -m redteam_audit.run --config B --attacks ext-02,ind-03 --max-cost 0.25

Every API response is cached in results/cache/, so re-running costs nothing and C reuses B's replies.
"""

from __future__ import annotations

import argparse
import sys
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone

from . import llm
from .attacks import Attack, load_attacks
from .detectors import detect
from .guardrails import guard
from .judge import judge_attack
from .kb import ROOT
from .llm import BOT_MODEL, JUDGE_MODEL, BudgetExceeded, Usage
from .metrics import summarize
from .target import SupportBot
from .utility import load_benign, run_case

RESULTS_DIR = ROOT / "results"

CONFIGS = {
    "A": {"prompt": "v2", "guarded": False, "label": "Baseline (prompt v2)"},
    "B": {"prompt": "v3", "guarded": False, "label": "Security-hardened prompt (v3)"},
    "C": {"prompt": "v3", "guarded": True, "label": "Security-hardened prompt + output guardrails"},
    # Positive control: a deliberately misconfigured prompt (planted bug), to prove the suite catches real failures.
    "M": {"prompt": "v2-misconfigured", "guarded": False, "label": "Planted bug: misconfigured prompt"},
    "MG": {"prompt": "v2-misconfigured", "guarded": True, "label": "Planted bug + output guardrails"},
}


def run_attack(attack: Attack, bot: SupportBot, guarded: bool, bot_usage: Usage, judge_usage: Usage) -> dict:
    turns, results, blocks = bot.converse(attack.turns, bot_usage, screen=guard if guarded else None)
    detections: dict[str, list[str]] = {}
    for r in results:
        for name, hits in detect(r.reply).items():
            detections.setdefault(name, []).extend(hits)
    verdict = judge_attack(attack, [(t.role, t.content) for t in turns], judge_usage)
    outcome = verdict.outcome if verdict else "error"
    return {
        "id": attack.id,
        "category": attack.category,
        "severity": attack.severity,
        "goal": attack.goal,
        "variant_of": attack.variant_of,
        "transcript": [asdict(t) for t in turns],
        "actions": [r.action for r in results],
        "retrieved": [r.retrieved_ids for r in results],
        "blocked_by": blocks,
        "detections": detections,
        "judge": verdict.model_dump() if verdict else None,
        "outcome": outcome,
        # Any detector firing is a security failure in its own right, whatever the attack's goal.
        "success": outcome == "full" or bool(detections),
    }


def run_config(name: str, attacks: list[Attack], benign: list[dict], workers: int, model: str) -> dict | None:
    cfg = CONFIGS[name]
    bot = SupportBot(cfg["prompt"], model=model)
    bot_usage, judge_usage = Usage(), Usage()
    print(f"\n[{name}] {cfg['label']} on {model}: {len(attacks)} attacks, {len(benign)} utility conversations")

    def safely(fn, item):
        try:
            return fn(item)
        except BudgetExceeded:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        attack_records = list(pool.map(lambda a: safely(lambda x: run_attack(x, bot, cfg["guarded"], bot_usage, judge_usage), a), attacks))
        utility_records = list(pool.map(lambda c: safely(lambda x: run_case(x, bot, bot_usage, cfg["guarded"]), c), benign))

    spent = bot_usage.spent_this_run_usd + judge_usage.spent_this_run_usd
    hits, calls = bot_usage.cache_hits + judge_usage.cache_hits, bot_usage.calls + judge_usage.calls
    print(f"  API calls: {calls - hits} new, {hits} reused | spent: ${spent:.4f}")
    if None in attack_records or None in utility_records:
        print("  Stopped by the spend cap. Responses so far are saved; raise --max-cost and run again to continue.")
        return None

    for r in attack_records:
        flag = "SUCCESS" if r["success"] else ("partial" if r["outcome"] == "partial" else "resisted")
        if flag != "resisted":
            print(f"    {flag:<8} {r['id']:<18} {', '.join(r['detections']) or r['outcome']}")

    return {
        "config": name,
        **cfg,
        "bot_model": bot.model,
        "judge_model": JUDGE_MODEL,
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "bot_usage": asdict(bot_usage),
        "judge_usage": asdict(judge_usage),
        "summary": summarize(attack_records, utility_records),
        "attacks": attack_records,
        "utility": utility_records,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", nargs="+", default=["A", "B", "C"], choices=list(CONFIGS))
    parser.add_argument("--attacks", help="comma-separated attack ids (partial run)")
    parser.add_argument("--no-utility", action="store_true", help="skip the utility check")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--bot-model", default=BOT_MODEL, help="model under attack (results for non-default models get their own files)")
    parser.add_argument("--max-cost", type=float, help="spend cap in USD for new API calls across this run")
    args = parser.parse_args()
    if args.max_cost is not None:
        llm.MAX_RUN_COST_USD = args.max_cost
    print(f"Spend cap for new API calls: ${llm.MAX_RUN_COST_USD:.2f} (saved responses are free)")

    attacks = load_attacks()
    if args.attacks:
        wanted = set(args.attacks.split(","))
        attacks = [a for a in attacks if a.id in wanted]
    benign = [] if args.no_utility or args.attacks else load_benign()
    partial = bool(args.attacks)

    RESULTS_DIR.mkdir(exist_ok=True)
    for name in args.config:
        output = run_config(name, attacks, benign, args.workers, args.bot_model)
        if output is None:
            # Stopped by the spend cap: fail loudly so CI can't go on to use older results.
            sys.exit(1)
        s = output["summary"]
        print(
            f"  ASR {s['asr']:.0%} ({s['successes']}/{s['attacks']}) | severity-weighted {s['asr_weighted']:.0%} | "
            f"partial {s['partials']} | utility pass {s['utility_pass_rate']:.0%} | over-refusal {s['over_refusal_rate']:.0%}"
        )
        model_tag = "" if args.bot_model == BOT_MODEL else f"@{args.bot_model}"
        path = RESULTS_DIR / f"config-{name}{model_tag}{'-partial' if partial else ''}.json"
        path.write_text(json.dumps(output, indent=2, ensure_ascii=False))
        print(f"  Saved {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
