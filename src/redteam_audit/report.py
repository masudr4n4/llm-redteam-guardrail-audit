"""Build the static HTML report (docs/index.html) from results/config-{A,B,C}.json.

    uv run python -m redteam_audit.report
"""

from __future__ import annotations

import json
from html import escape

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .attacks import load_attacks
from .kb import ROOT
from .metrics import CATEGORIES

RESULTS = ROOT / "results"
OUT = ROOT / "docs" / "index.html"
TEMPLATES = ROOT / "src" / "redteam_audit" / "templates"

CATEGORY_LABELS = {
    "override": "Instruction override",
    "extraction": "Secret / prompt extraction",
    "indirect": "Indirect injection (poisoned articles)",
    "commitment": "Unauthorized commitments",
    "phishing": "Phishing & data harvesting",
    "jailbreak": "Jailbreaks & harmful help",
    "multi_turn": "Multi-turn escalation",
    "obfuscated": "Obfuscated variants",
}
# Series order follows the categorical palette: slot 1 = final defense, slot 2 = baseline, slot 3 = middle.
SERIES = [("A", "s2"), ("B", "s3"), ("C", "s1")]


def _bar_path(x: float, y: float, w: float, h: float, r: float = 4) -> str:
    r = min(r, w / 2, h / 2)
    return f"M{x},{y} H{x + w - r} Q{x + w},{y} {x + w},{y + r} V{y + h - r} Q{x + w},{y + h} {x + w - r},{y + h} H{x} Z"


def category_chart(runs: dict[str, dict]) -> str:
    """Grouped horizontal bars: attack success rate per category for each configuration."""
    cats = [c for c in CATEGORIES if c in runs["A"]["summary"]["by_category"]]
    label_w, plot_w, right = 250, 400, 56
    bar_h, gap = 11, 2
    row_h = 3 * (bar_h + gap) + 16
    width, height = label_w + plot_w + right, 28 + row_h * len(cats)
    x = lambda v: label_w + v * plot_w  # noqa: E731

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Attack success rate by category" class="chart">']
    for tick in (0, 0.25, 0.5, 0.75, 1):
        parts.append(f'<line x1="{x(tick)}" x2="{x(tick)}" y1="18" y2="{height}" class="grid"/>')
        parts.append(f'<text x="{x(tick)}" y="12" class="tick" text-anchor="middle">{tick:.0%}</text>')
    for i, cat in enumerate(cats):
        y0 = 26 + i * row_h
        total = runs["A"]["summary"]["by_category"][cat]["total"]
        parts.append(f'<text x="{label_w - 12}" y="{y0 + 12}" class="cat" text-anchor="end">{CATEGORY_LABELS[cat]}</text>')
        parts.append(f'<text x="{label_w - 12}" y="{y0 + 27}" class="tick" text-anchor="end">n = {total}</text>')
        for j, (name, cls) in enumerate(SERIES):
            s = runs[name]["summary"]["by_category"][cat]
            y = y0 + j * (bar_h + gap)
            w = max(s["asr"] * plot_w, 2)
            tip = f'{CATEGORY_LABELS[cat]} · config {name}: {s["successes"]}/{s["total"]} attacks succeeded ({s["asr"]:.0%})'
            parts.append(
                f'<g class="bar"><title>{escape(tip)}</title><path d="{_bar_path(label_w, y, w, bar_h)}" class="{cls}"/>'
                f'<rect x="{label_w}" y="{y - 1}" width="{plot_w}" height="{bar_h + 2}" class="hit"/></g>'
            )
            parts.append(f'<text x="{x(s["asr"]) + 6}" y="{y + bar_h - 2}" class="val">{s["successes"]}/{s["total"]}</text>')
    parts.append(f'<line x1="{label_w}" x2="{label_w}" y1="18" y2="{height}" class="axis"/>')
    parts.append("</svg>")
    return "".join(parts)


def attack_rows(runs: dict[str, dict]) -> list[dict]:
    """One row per attack that succeeded or partly succeeded in any configuration, with all three outcomes."""
    by_id = {name: {a["id"]: a for a in run["attacks"]} for name, run in runs.items()}
    rows = []
    for a in runs["A"]["attacks"]:
        per = {name: by_id[name][a["id"]] for name in runs}
        if any(p["success"] or p["outcome"] == "partial" for p in per.values()):
            rows.append({"attack": a, "per": per})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(key=lambda r: (not r["per"]["C"]["success"], not r["per"]["B"]["success"], order[r["attack"]["severity"]]))
    return rows


def main() -> None:
    runs = {name: json.loads((RESULTS / f"config-{name}.json").read_text()) for name in "ABC"}
    # Control runs: the same suite on a cheaper model, and on a deliberately misconfigured prompt.
    control_files = [f"config-{n}@gpt-6-luna.json" for n in "ABC"] + ["config-M.json", "config-MG.json"]
    controls = [json.loads((RESULTS / f).read_text()) for f in control_files if (RESULTS / f).exists()]
    attack_meta = {a.id: a for a in load_attacks()}
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    # Real spend comes from the unique saved responses: configurations that reuse another's replies (C, MG) would
    # otherwise be counted twice.
    total_cost = sum(json.loads(p.read_text())["cost_usd"] for p in (RESULTS / "cache").glob("*.json"))
    html = env.get_template("report.html.j2").render(
        runs=runs,
        A=runs["A"]["summary"],
        B=runs["B"]["summary"],
        C=runs["C"]["summary"],
        chart=category_chart(runs),
        labels=CATEGORY_LABELS,
        categories=[c for c in CATEGORIES if c in runs["A"]["summary"]["by_category"]],
        rows=attack_rows(runs),
        attack_meta=attack_meta,
        controls=controls,
        total_cost=total_cost,
    )
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(html)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
