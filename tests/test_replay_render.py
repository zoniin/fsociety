"""Replay rendering of real-model traces."""

from __future__ import annotations

from pathlib import Path

from interpose.cli import main

TRACE = (Path(__file__).resolve().parents[1] / "results" / "real-model-pilot" / "traces"
         / "run_ed32da08ac8b" / "run_7f59152c3ca1.events.jsonl")


def test_multiline_model_text_stays_on_one_line(capsys) -> None:
    assert main(["replay", str(TRACE), "--verbose"]) == 0
    lines = capsys.readouterr().out.splitlines()
    msg = [ln for ln in lines if "agent.message" in ln]
    assert msg and all(len(ln) < 160 for ln in msg)
    # Every event line still starts with its timestamp column.
    body = [ln for ln in lines if ln.startswith("     ")]
    assert all(ln.split()[0].replace(".", "").isdigit() for ln in body)


def test_absence_checks_read_as_absences(capsys) -> None:
    main(["replay", str(TRACE)])
    row = next(ln for ln in capsys.readouterr().out.splitlines() if "no_undetected_flow" in ln)
    assert "no protected read" in row
