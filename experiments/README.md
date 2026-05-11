# experiments/

Self-contained handover package for the LLM-driven investigation workflow.
This is the **tracked** copy of the inputs needed to run an investigation;
the working/output directory remains `paper_graphs_v2/experiments/`
(gitignored — produces large `.cypher` / `.duckdb` outputs).

If you cloned the repo and want to run an investigation, work from here.

## Layout

```
experiments/
├── investigation_prompt_v3.md    canonical investigation prompt
├── raw_logs_prompt.md            alternate prompt (raw-log style)
├── evaluate.py                   detection scorer
├── ics-attack.json               MITRE ATT&CK for ICS, STIX 2.0
├── assets.yaml                   asset inventory (LLM-flavor, old schema)
├── <scenario>_gt.yaml            hand-curated ground truth, latest version
│                                 per scenario (be/frosty/fuxnet/id2/pipe/triton)
└── <scenario>_24h/               per-scenario sandbox
    ├── assets.yaml               → symlink to ../assets.yaml
    ├── ics-attack.json           → symlink to ../ics-attack.json
    └── *_invariants.json         pre-mined invariants
```

## How to run an investigation

1. Load the augmented Cypher for the scenario into Neo4j:
   `bash purge_db.sh <path>/augmented_<Scenario>.cypher`
2. `cd experiments/<scenario>_24h/` — switch to the sandbox so the
   prompt's CWD-relative references resolve.
3. Feed `../investigation_prompt_v3.md` to the LLM (or copy it to the
   sandbox dir if the LLM tool requires a local path). Follow its
   step-by-step procedure.
4. Save the model's structured detections to `detections.yaml` in the
   sandbox dir.

## How to score

```bash
cd experiments
python3 evaluate.py \
  --groundtruth be_gt.yaml \
  --detections  be_24h/detections.yaml
```

Technique-agnostic: TP iff `(src, rel, dst)` triple is present in both
ground truth and detections. The MITRE technique label is commentary,
not part of the key.

## Notes

- The ground truth files here are the **latest curation pass** for each
  scenario, renamed without the version suffix:
    | Tracked file       | Source (paper_graphs_v2/experiments/) |
    | ---                | ---                                   |
    | `be_gt.yaml`       | `be_gt2.yaml`                         |
    | `frosty_gt.yaml`   | `frosty_gt1.yaml`                     |
    | `fuxnet_gt.yaml`   | `fuxnet_gt.yaml`                      |
    | `id2_gt.yaml`      | `id2_gt1.yaml`                        |
    | `pipe_gt.yaml`     | `pipe_gt.yaml`                        |
    | `triton_gt.yaml`   | `triton_gt.yaml`                      |
- No GT yet for `id_24h` (Industroyer original) or `stuxnet_24h`;
  invariants are still included so the process-level subagent has
  something to read.
- `fuxnet_24h/` has no invariants generated yet (signal DB existed but
  was not mined). Run `python3 -m network_aug.invariants` against the
  Fuxnet signal DuckDB to populate it.
- The shared `assets.yaml` here uses the **old** `ip_address: str`
  schema — the LLM tooling was tuned against it. Do not replace with
  `ICSGraph/Collection/assets.yaml` (`ip_addresses: [list]`) without
  testing the prompt against the new shape.
- Ground truth files are **hand-curated and actively evolving**. Treat
  them as best-effort. When you make a curation pass, copy the latest
  back into this dir to keep the handover package current.
