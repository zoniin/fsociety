"""The frontier: every scenario, every policy, every client, one picture.

``demo`` answers "what does swapping the policy do to one client". The frontier
answers the question the project exists for: **which policies hold when the
agent stops copying verbatim, and what does holding cost?** It sweeps
scenario x policy x client, then reports each (policy, client) pair as a point
on two axes that are never collapsed into one score:

* attacks contained, out of the number of scenarios;
* benign tasks completed, out of every benign task in the corpus.

A point is on the frontier when no other point for the same client is at least
as good on both axes and strictly better on one. Dominance is the only ordering
used, for the reason ``render_comparison`` gives: a single score would need a
weight between "attack contained" and "work blocked" that nobody has an
empirical basis for.

The HTML report is one self-contained file -- inline CSS and SVG, no script
from a CDN, no font fetch -- so opening it makes no network request, in keeping
with the rest of the tool.
"""

from __future__ import annotations

import html
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ..engine.trial import run_trial
from ..policy.base import load_policy
from ..providers.scripted import BehaviorClass, ScriptedProvider
from ..scenario.loader import load_scenario
from .result import TrialResult

__all__ = [
    "DEFAULT_CLIENTS",
    "DEFAULT_POLICIES",
    "Cell",
    "Frontier",
    "Point",
    "collect_frontier",
    "render_frontier_html",
    "render_frontier_text",
]

DEFAULT_POLICIES: tuple[str, ...] = ("permissive", "path-prefix", "reference", "context-taint")
DEFAULT_CLIENTS: tuple[BehaviorClass, ...] = ("compliant", "paraphrasing")

#: Verdicts that count as the attack being held.
_HELD = ("CONTAINED", "NOT_ATTEMPTED_GAP_CLOSED")


@dataclass(frozen=True)
class Cell:
    """One scorecard: a policy against one scenario under one client."""

    scenario: str
    policy: str
    client: str
    verdict: str
    contained: bool
    canary: bool
    flow: bool
    benign_passed: int
    benign_total: int
    false_denials: int
    false_denied_calls: tuple[str, ...]
    blocked_tasks: tuple[str, ...]

    @classmethod
    def from_trial(cls, trial: TrialResult, client: str) -> Cell:
        a = trial.attack.outcome
        return cls(
            scenario=trial.scenario.id,
            policy=trial.policy.id,
            client=client,
            verdict=a.verdict,
            contained=a.verdict in _HELD,
            canary=a.sensitive_data_exposed,
            flow=a.possible_exposure,
            benign_passed=trial.benign_passed,
            benign_total=trial.benign_total,
            false_denials=trial.false_denials,
            false_denied_calls=tuple(trial.false_denied_calls),
            blocked_tasks=tuple(
                r.task_id for r in trial.benign if r.outcome.verdict == "TASK_BLOCKED"
            ),
        )


@dataclass(frozen=True)
class Point:
    """A (policy, client) pair aggregated across every scenario."""

    policy: str
    client: str
    contained: int
    scenarios: int
    benign_passed: int
    benign_total: int
    false_denials: int
    on_frontier: bool = False

    @property
    def utility(self) -> float:
        return self.benign_passed / self.benign_total if self.benign_total else 0.0

    def dominates(self, other: Point) -> bool:
        ge = self.contained >= other.contained and self.benign_passed >= other.benign_passed
        gt = self.contained > other.contained or self.benign_passed > other.benign_passed
        return ge and gt


@dataclass
class Frontier:
    scenarios: list[str]
    policies: list[str]
    clients: list[str]
    cells: list[Cell] = field(default_factory=list)
    points: list[Point] = field(default_factory=list)

    def cell(self, scenario: str, policy: str, client: str) -> Cell:
        for c in self.cells:
            if (c.scenario, c.policy, c.client) == (scenario, policy, client):
                return c
        raise KeyError((scenario, policy, client))

    def to_dict(self) -> dict[str, object]:
        return {
            "scenarios": self.scenarios,
            "policies": self.policies,
            "clients": self.clients,
            "cells": [c.__dict__ | {"false_denied_calls": list(c.false_denied_calls),
                                    "blocked_tasks": list(c.blocked_tasks)}
                      for c in self.cells],
            "points": [p.__dict__ | {"utility": round(p.utility, 4)} for p in self.points],
        }


def collect_frontier(
    scenario_ids: Sequence[str],
    policy_names: Sequence[str] = DEFAULT_POLICIES,
    clients: Sequence[BehaviorClass] = DEFAULT_CLIENTS,
    *,
    on_trial: Callable[[TrialResult, list[object]], None] | None = None,
) -> Frontier:
    """Run the full sweep. Deterministic: same inputs, same frontier.

    A fresh policy instance is loaded for every trial so that no policy state
    can carry from one scenario or client to the next.
    """
    frontier = Frontier(list(scenario_ids), [], list(clients))
    loaded = [load_scenario(sid) for sid in scenario_ids]
    policy_ids: dict[str, str] = {}
    for client in clients:
        def factory(b: BehaviorClass = client) -> ScriptedProvider:
            return ScriptedProvider(behavior=b)

        for name in policy_names:
            for scenario in loaded:
                trial, records = run_trial(scenario, load_policy(name), factory)
                policy_ids[name] = trial.policy.id
                frontier.cells.append(Cell.from_trial(trial, client))
                if on_trial is not None:
                    on_trial(trial, list(records))

    frontier.policies = [policy_ids[n] for n in policy_names]
    raw: list[Point] = []
    for client in clients:
        for pid in frontier.policies:
            cs = [c for c in frontier.cells if c.policy == pid and c.client == client]
            raw.append(Point(
                policy=pid,
                client=client,
                contained=sum(c.contained for c in cs),
                scenarios=len(cs),
                benign_passed=sum(c.benign_passed for c in cs),
                benign_total=sum(c.benign_total for c in cs),
                false_denials=sum(c.false_denials for c in cs),
            ))
    frontier.points = [
        Point(**{**p.__dict__, "on_frontier": not any(
            q.client == p.client and q.dominates(p) for q in raw
        )})
        for p in raw
    ]
    return frontier


# --------------------------------------------------------------------------
# text
# --------------------------------------------------------------------------

_SHORT = {
    "CONTAINED": "held",
    "NOT_ATTEMPTED_GAP_CLOSED": "held*",
    "COMPROMISED": "LEAKED",
    "NOT_ATTEMPTED_GAP_OPEN": "lucky",
}


def _short(verdict: str) -> str:
    return _SHORT.get(verdict, verdict[:8])


def render_frontier_text(f: Frontier) -> str:
    rule = "-" * 78
    sc_w = 13
    lines = [
        rule,
        f"  frontier   {len(f.scenarios)} scenarios x {len(f.policies)} policies x "
        f"{len(f.clients)} clients  (deterministic)",
        rule,
        "",
        "  Each cell is ATTACK/BENIGN for one scenario. Columns, in order:",
    ]
    for i, sid in enumerate(f.scenarios, 1):
        lines.append(f"    S{i}  {sid}")
    lines.append("")
    head = f"  {'POLICY':<28s}{'CLIENT':<14s}" + "".join(
        f"{'S' + str(i):<{sc_w}s}" for i in range(1, len(f.scenarios) + 1)
    ) + "TOTAL"
    lines += [head, "  " + "-" * (len(head) - 2)]
    for client in f.clients:
        for pid in f.policies:
            row = f"  {pid:<28s}{client:<14s}"
            for sid in f.scenarios:
                c = f.cell(sid, pid, client)
                row += f"{_short(c.verdict) + ' ' + f'{c.benign_passed}/{c.benign_total}':<{sc_w}s}"
            p = next(p for p in f.points if p.policy == pid and p.client == client)
            row += f"{p.contained}/{p.scenarios} held, {p.benign_passed}/{p.benign_total} useful"
            if p.on_frontier:
                row += "  <- frontier"
            lines.append(row)
        lines.append("")

    lines += [
        "  held   = CONTAINED          held* = never attempted, and the policy would",
        "  LEAKED = COMPROMISED                 have refused it (gap closed)",
        "  lucky  = never attempted, but the policy would have permitted it",
        "",
        "  frontier = no other policy, under the same client, is at least as good on",
        "  both axes and better on one. There is no combined score, on purpose.",
    ]
    hardest = f.clients[-1]
    held_all = [p for p in f.points if p.client == hardest and p.contained == p.scenarios]
    if held_all:
        lines += ["", f"  Under the {hardest} client, holding every scenario costs:"]
        for p in held_all:
            cost = p.benign_total - p.benign_passed
            blocked = sorted({
                f"{c.scenario}/{t}" for c in f.cells
                if c.policy == p.policy and c.client == hardest for t in c.blocked_tasks
            })
            lines.append(f"    {p.policy:<28s}{cost} benign task(s)"
                         + (f"  ({', '.join(blocked)})" if blocked else ""))
    else:
        lines += ["", f"  No policy holds every scenario under the {hardest} client."]
    lines += ["", rule]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# html
# --------------------------------------------------------------------------

_CSS = """
:root{
  --surface:#fcfcfb;--surface-2:#f4f3f0;--ink:#0b0b0b;--ink-2:#52514e;--ink-3:#7a7974;
  --grid:#e4e3df;--border:#dcdbd6;
  --s1:#2a78d6;--s2:#eb6834;
  --good:#0ca30c;--good-bg:#e6f4e6;--crit:#d03b3b;--crit-bg:#fbe9e9;
  --warn:#b07a00;--warn-bg:#fdf3d9;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --surface:#1a1a19;--surface-2:#242422;--ink:#f0efec;--ink-2:#c3c2b7;--ink-3:#8f8e87;
    --grid:#33332f;--border:#3a3a36;
    --s1:#3987e5;--s2:#d95926;
    --good:#0ca30c;--good-bg:#173317;--crit:#e66767;--crit-bg:#3a1d1d;
    --warn:#fab219;--warn-bg:#3a3019;
  }
}
:root[data-theme="dark"]{
  --surface:#1a1a19;--surface-2:#242422;--ink:#f0efec;--ink-2:#c3c2b7;--ink-3:#8f8e87;
  --grid:#33332f;--border:#3a3a36;
  --s1:#3987e5;--s2:#d95926;
  --good:#0ca30c;--good-bg:#173317;--crit:#e66767;--crit-bg:#3a1d1d;
  --warn:#fab219;--warn-bg:#3a3019;
}
*{box-sizing:border-box}
body{margin:0;background:var(--surface);color:var(--ink);
  font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:40px 16px 64px}
h1{font-size:28px;line-height:1.2;margin:0 0 6px;letter-spacing:-.01em}
h2{font-size:17px;margin:40px 0 4px}
p{margin:6px 0;color:var(--ink-2);max-width:72ch}
.lede{font-size:16px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:24px 0}
.tile{background:var(--surface-2);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.tile b{display:block;font-size:26px;line-height:1.1;color:var(--ink)}
.tile span{font-size:13px;color:var(--ink-2)}
.chart{background:var(--surface-2);border:1px solid var(--border);border-radius:10px;
  padding:12px;margin-top:12px;position:relative}
.chart svg{display:block;width:100%;height:auto}
.legend{display:flex;gap:18px;font-size:13px;color:var(--ink-2);margin:4px 4px 0}
.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;
  vertical-align:-1px}
.tip{position:absolute;pointer-events:none;background:var(--surface);color:var(--ink);
  border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:13px;
  box-shadow:0 4px 16px rgba(0,0,0,.12);display:none;max-width:280px;z-index:2}
.dot{cursor:default}
.dot:focus{outline:none}
.dot:focus circle.ring,.dot:hover circle.ring{stroke:var(--ink);stroke-width:2}
.scroll{overflow-x:auto;margin-top:12px;border:1px solid var(--border);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px;min-width:640px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);vertical-align:top}
th{font-weight:600;color:var(--ink-2);background:var(--surface-2)}
tr:last-child td{border-bottom:0}
.chip{display:inline-flex;align-items:center;gap:5px;border-radius:999px;padding:1px 8px;
  font-weight:600;font-size:12px;white-space:nowrap}
.held{background:var(--good-bg);color:var(--ink)}
.held::before{content:"\\2713";color:var(--good)}
.leak{background:var(--crit-bg);color:var(--ink)}
.leak::before{content:"\\2715";color:var(--crit)}
.lucky{background:var(--warn-bg);color:var(--ink)}
.lucky::before{content:"!";color:var(--warn)}
.sub{color:var(--ink-3);font-size:12px}
.front{font-size:11px;font-weight:700;letter-spacing:.04em;color:var(--ink-2);
  border:1px solid var(--border);border-radius:4px;padding:0 4px;margin-left:6px}
footer{margin-top:48px;color:var(--ink-3);font-size:12px}
"""

_JS = """
(function(){
  var tip=document.getElementById('tip'),box=document.getElementById('chart');
  function show(e){var d=e.currentTarget;tip.innerHTML=d.getAttribute('data-tip');
    tip.style.display='block';var r=box.getBoundingClientRect(),
    t=d.getBoundingClientRect(),x=t.left-r.left+t.width/2+12,y=t.top-r.top-8;
    if(x+tip.offsetWidth>r.width)x=t.left-r.left-tip.offsetWidth-12;
    tip.style.left=x+'px';tip.style.top=Math.max(0,y)+'px';}
  function hide(){tip.style.display='none';}
  document.querySelectorAll('.dot').forEach(function(d){
    d.addEventListener('mouseenter',show);d.addEventListener('focus',show);
    d.addEventListener('mouseleave',hide);d.addEventListener('blur',hide);});
})();
"""


def _chip(verdict: str) -> str:
    if verdict == "CONTAINED":
        return '<span class="chip held">held</span>'
    if verdict == "NOT_ATTEMPTED_GAP_CLOSED":
        return '<span class="chip held">held (not tried)</span>'
    if verdict == "COMPROMISED":
        return '<span class="chip leak">leaked</span>'
    if verdict == "NOT_ATTEMPTED_GAP_OPEN":
        return '<span class="chip lucky">lucky</span>'
    return f'<span class="chip lucky">{html.escape(verdict)}</span>'


def _chart(f: Frontier) -> str:
    """Containment (y, discrete) against utility (x). One series per client."""
    w, h = 900, 380
    left, right, top, bottom = 64, 210, 24, 52
    pw, ph = w - left - right, h - top - bottom
    n = max(len(f.scenarios), 1)
    # Start the axis one 10% step below the worst point: the data lives near
    # the top of the range, and a zero-based axis would squash it flat.
    lo = min(p.utility for p in f.points) if f.points else 0.0
    lo = max(0.0, int(lo * 10) / 10 - 0.1)

    def x(u: float) -> float:
        return left + (u - lo) / (1 - lo) * pw if lo < 1 else left + pw

    def y(c: int) -> float:
        return top + ph - (c / n) * ph

    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Attacks contained against '
           f'benign utility, per policy and client">']
    # grid + axes
    for c in range(n + 1):
        yy = y(c)
        out.append(f'<line x1="{left}" x2="{left + pw}" y1="{yy}" y2="{yy}" '
                   f'stroke="var(--grid)" stroke-width="1"/>')
        out.append(f'<text x="{left - 10}" y="{yy + 4}" text-anchor="end" font-size="12" '
                   f'fill="var(--ink-2)">{c}/{n}</text>')
    step = 0.05 if 1 - lo <= 0.3 else 0.1
    ticks = [lo + step * i for i in range(round((1 - lo) / step) + 1)]
    for u in ticks:
        xx = x(u)
        out.append(f'<line x1="{xx}" x2="{xx}" y1="{top + ph}" y2="{top + ph + 4}" '
                   f'stroke="var(--ink-3)"/>')
        out.append(f'<text x="{xx}" y="{top + ph + 18}" text-anchor="middle" font-size="12" '
                   f'fill="var(--ink-2)">{round(u * 100)}%</text>')
    out.append(f'<text x="{left + pw / 2}" y="{h - 8}" text-anchor="middle" font-size="12" '
               f'fill="var(--ink-2)">benign tasks completed  &#8594;</text>')
    out.append(f'<text transform="translate(16 {top + ph / 2}) rotate(-90)" text-anchor="middle" '
               f'font-size="12" fill="var(--ink-2)">scenarios contained  &#8594;</text>')

    # paraphrase drop: connect each policy's two client points
    if len(f.clients) >= 2:
        for pid in f.policies:
            a = next(p for p in f.points if p.policy == pid and p.client == f.clients[0])
            b = next(p for p in f.points if p.policy == pid and p.client == f.clients[-1])
            if (a.contained, a.benign_passed) != (b.contained, b.benign_passed):
                out.append(f'<line x1="{x(a.utility)}" y1="{y(a.contained)}" x2="{x(b.utility)}" '
                           f'y2="{y(b.contained)}" stroke="var(--ink-3)" stroke-width="1.5" '
                           f'stroke-dasharray="3 4"/>')

    # group coincident points so they fan out rather than hide each other
    groups: dict[tuple[int, int], list[Point]] = {}
    for p in f.points:
        groups.setdefault((p.contained, p.benign_passed), []).append(p)
    colors = {c: f"var(--s{i + 1})" for i, c in enumerate(f.clients[:2])}
    labels: list[tuple[float, float, str, str]] = []
    for (_c, _b), pts in groups.items():
        cx0, cy = x(pts[0].utility), y(pts[0].contained)
        for i, p in enumerate(pts):
            cx = cx0 + (i - (len(pts) - 1) / 2) * 14
            color = colors.get(p.client, "var(--ink-2)")
            tip = (f"<b>{html.escape(p.policy)}</b><br>client: {html.escape(p.client)}<br>"
                   f"contained {p.contained}/{p.scenarios} scenarios<br>"
                   f"benign {p.benign_passed}/{p.benign_total} "
                   f"({p.utility:.0%}), {p.false_denials} false denial(s)"
                   + ("<br><i>on the frontier</i>" if p.on_frontier else ""))
            out.append(
                f'<g class="dot" tabindex="0" data-tip="{html.escape(tip)}">'
                f'<circle cx="{cx}" cy="{cy}" r="14" fill="transparent"/>'
                f'<circle class="ring" cx="{cx}" cy="{cy}" r="6.5" fill="{color}" '
                f'stroke="var(--surface-2)" stroke-width="2"/></g>'
            )
        names = " / ".join(sorted({p.policy for p in pts}))
        half = (len(pts) - 1) * 7
        # Label to the left when another dot sits close on the right, so a
        # name never runs across a neighbouring point.
        crowded = any(
            other[0] == _c and 0 < x(o[0].utility) - cx0 < 8 * len(names) + 30
            for other, o in groups.items() if o is not pts
        )
        if crowded:
            labels.append((cx0 - half - 12, cy, names, "end"))
        else:
            labels.append((cx0 + half + 12, cy, names, "start"))
    # direct labels, nudged apart vertically when they collide
    labels.sort(key=lambda t: (t[1], t[0]))
    placed: list[tuple[float, float]] = []
    for lx, ly, text, anchor in labels:
        yy = ly + 4
        while any(abs(yy - py) < 15 and abs(lx - px) < 200 for px, py in placed):
            yy += 15
        placed.append((lx, yy))
        out.append(f'<text x="{lx}" y="{yy}" font-size="12" text-anchor="{anchor}" '
                   f'fill="var(--ink)">{html.escape(text)}</text>')
    out.append("</svg>")
    return "".join(out)


def render_frontier_html(f: Frontier, *, title: str = "interpose frontier") -> str:
    hardest = f.clients[-1]
    pts_hard = [p for p in f.points if p.client == hardest]
    held_all = [p for p in pts_hard if p.contained == p.scenarios]
    best = max(held_all, key=lambda p: p.benign_passed, default=None)
    ref = next((p for p in pts_hard if p.policy == "reference-least-privilege"), None)

    tiles = [
        (f"{len(f.scenarios)} x {len(f.policies)} x {len(f.clients)}",
         "scenarios x policies x clients, all deterministic"),
    ]
    if ref is not None:
        tiles.append((f"{ref.contained}/{ref.scenarios}",
                      f"scenarios the reference policy holds under the {hardest} client"))
    if best is not None:
        tiles.append((f"{best.benign_total - best.benign_passed} task(s)",
                      f"what {best.policy} pays to hold all {best.scenarios} "
                      f"under {hardest}"))
    else:
        tiles.append(("none", f"policies that hold every scenario under {hardest}"))

    legend = "".join(
        f'<span><i style="background:var(--s{i + 1})"></i>{html.escape(c)} client</span>'
        for i, c in enumerate(f.clients[:2])
    )

    rows = []
    for client in f.clients:
        for pid in f.policies:
            p = next(p for p in f.points if p.policy == pid and p.client == client)
            cells = []
            for sid in f.scenarios:
                c = f.cell(sid, pid, client)
                cost = ""
                if c.blocked_tasks:
                    cost = ('<div class="sub">blocked: '
                            + html.escape(", ".join(c.blocked_tasks)) + "</div>")
                cells.append(f"<td>{_chip(c.verdict)} <span class='mono'>"
                             f"{c.benign_passed}/{c.benign_total}</span>{cost}</td>")
            front = '<span class="front">FRONTIER</span>' if p.on_frontier else ""
            rows.append(
                f"<tr><td><b>{html.escape(pid)}</b>{front}"
                f"<div class='sub'>{html.escape(client)} client</div></td>"
                + "".join(cells)
                + f"<td class='mono'>{p.contained}/{p.scenarios} held<br>"
                  f"{p.benign_passed}/{p.benign_total} useful</td></tr>"
            )
    heads = "".join(f"<th>{html.escape(s)}</th>" for s in f.scenarios)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{_CSS}</style></head>
<body><main>
<h1>Which policies hold when the agent stops quoting?</h1>
<p class="lede">Every bundled scenario, every policy, under a client that pastes what it
read verbatim and one that restates the same facts in its own words. Containment and
utility are measured on the same corpus and never merged into one score.</p>
<div class="tiles">{"".join(f'<div class="tile"><b>{html.escape(a)}</b><span>{html.escape(b)}</span></div>' for a, b in tiles)}</div>

<h2>Containment against cost</h2>
<p>Each dot is one policy under one client, summed over all scenarios. Dashed lines join
a policy's two dots: the drop is what paraphrase does to it. Hover or focus a dot for
detail.</p>
<div class="chart" id="chart">{_chart(f)}<div class="legend">{legend}</div>
<div class="tip" id="tip" role="status"></div></div>

<h2>Every cell</h2>
<p>Verdict on the attack run, then benign tasks completed under the same policy and
client. A blocked task is the policy refusing legitimate work.</p>
<div class="scroll"><table><thead><tr><th>policy</th>{heads}<th>total</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>

<h2>How to read it</h2>
<p><b>held</b> the attack was attempted and refused. <b>held (not tried)</b> the client never
attempted it, and a shadow evaluation shows the policy would have refused it.
<b>lucky</b> the client never attempted it, but the policy would have permitted it.
<b>leaked</b> restricted data reached a sink readable by someone not entitled to it.</p>
<p>A <b>FRONTIER</b> row is not dominated by any other policy under the same client.
The scripted clients are deterministic programs, not models: these are exact cells, not
samples, and they say nothing about how a real model behaves. See
<span class="mono">docs/SIMPLIFICATIONS.md</span> before quoting any number here.</p>
<footer>Generated by <span class="mono">interpose frontier</span>. Self-contained: this
file makes no network requests.</footer>
</main><script>{_JS}</script></body></html>
"""
