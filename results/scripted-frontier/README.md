# scripted-frontier, latest committed run

The deterministic headline sweep (`benchmarks/scripted-frontier.yaml`): all
four scenarios, every built-in policy, the verbatim and paraphrasing scripted
clients. Open `report.html` for the frontier chart and every cell;
`manifest.json` records the scenario and policy digests it was scored under.

It is deterministic, so the 40 per-trial logs are not committed: regenerate
them byte for byte with

```bash
interpose bench run scripted-frontier
```
