# Real-model pilot, 2026-11-19

Claude Opus 5.5 at low effort, one sample per cell. Write-up:
[`docs/research/REAL_MODEL_PILOT.md`](../../docs/research/REAL_MODEL_PILOT.md).

| File | What it is |
|---|---|
| `report.html` | The pilot as one frontier report (Opus cells, scenarios at v0.1.0) |
| `confidential-egress.json` | `frontier --json` for confidential-egress, with the paraphrasing scripted client alongside |
| `compartment-and-indirect.json` | `frontier --json` for the other two scenarios |
| `compartment-egress-v0.1.1.json` | One scorecard after the b2 fixture fix, confirming it |

To run it again (it now uses the v0.2.0 scenarios, which add `get_queue_readers`):

```bash
interpose bench plan real-model-pilot
```

```bash
interpose bench run real-model-pilot --yes
```
