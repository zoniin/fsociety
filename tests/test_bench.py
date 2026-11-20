"""Saved benchmarks (``interpose bench``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import interpose.bench as bench
from interpose.cli import main
from interpose.errors import UsageError


def test_every_saved_benchmark_loads_and_plans() -> None:
    found = bench.discover_benchmarks()
    assert {"real-model-pilot", "queue-visibility", "scripted-frontier",
            "scripted-long-session"} <= set(found)
    for path in found.values():
        spec, _ = bench.load_benchmark(str(path))
        assert bench.plan(spec).trials > 0


def test_paid_plan_is_estimated_from_measured_tokens() -> None:
    spec, _ = bench.load_benchmark("queue-visibility")
    p = bench.plan(spec)
    assert p.paid_trials == 3 and not p.deterministic
    assert p.estimated_input_tokens == 3 * 30142
    assert p.estimated_usd == pytest.approx(0.58, abs=0.01)


def test_scripted_clients_run_once_whatever_the_repeat(tmp_path) -> None:
    f = tmp_path / "b.yaml"
    f.write_text("name: t\ndescription: d\nscenarios: [confidential-egress]\n"
                 "policies: [reference]\nclients: [compliant]\nrepeat: 5\n", encoding="utf-8")
    spec, _ = bench.load_benchmark(str(f))
    assert bench.plan(spec).trials == 1


@pytest.mark.parametrize("body,match", [
    ("name: t\ndescription: d\nscenarios: [x]\npolicies: [reference]\nclients: [compliant]\n",
     "unknown scenarios"),
    ("name: t\ndescription: d\nscenarios: [confidential-egress]\npolicies: [nope]\n"
     "clients: [compliant]\n", "unknown policy"),
    ("name: t\ndescription: d\nscenarios: [confidential-egress]\npolicies: [reference]\n"
     "clients: [compliant]\nbudget: 5\n", "not a valid benchmark"),
])
def test_bad_specs_are_refused(tmp_path, body: str, match: str) -> None:
    from interpose.errors import PolicyLoadError

    f = tmp_path / "b.yaml"
    f.write_text(body, encoding="utf-8")
    with pytest.raises((UsageError, PolicyLoadError), match=match):
        bench.load_benchmark(str(f))


def test_a_paid_benchmark_never_runs_without_yes(monkeypatch, capsys) -> None:
    def boom(*a, **k):  # pragma: no cover - the point is that it is not reached
        raise AssertionError("ran a paid benchmark without --yes")

    monkeypatch.setattr(bench, "run_benchmark", boom)
    assert main(["bench", "run", "queue-visibility"]) == 0
    out = capsys.readouterr().out
    assert "Nothing has been spent" in out and "$0.58" in out


def test_free_benchmark_writes_a_complete_result(tmp_path, capsys) -> None:
    assert main(["bench", "run", "scripted-frontier", "--out", str(tmp_path)]) == 0
    (out,) = (tmp_path / "scripted-frontier").iterdir()
    for name in ("benchmark.yaml", "manifest.json", "frontier.json", "report.html"):
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["deterministic"] is True
    assert set(manifest["scenarios"]) == {"confidential-egress", "compartment-egress",
                                          "indirect-document-injection"}
    assert len(list((out / "runs").glob("*/result.json"))) == 30


def test_report_merges_saved_results_and_rejects_duplicates(tmp_path) -> None:
    pilot = Path(__file__).resolve().parents[1] / "results" / "real-model-pilot"
    out = tmp_path / "r.html"
    assert main(["bench", "report", str(pilot / "confidential-egress.json"),
                 str(pilot / "compartment-and-indirect.json"),
                 "--clients", "anthropic:claude-opus-5-5@low", "--out", str(out)]) == 0
    page = out.read_text(encoding="utf-8")
    assert "NOT deterministic" in page and "not completed by the client" in page

    from interpose.report.frontier import frontier_from_dicts

    d = json.loads((pilot / "confidential-egress.json").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="more than one"):
        frontier_from_dicts(d, d)
