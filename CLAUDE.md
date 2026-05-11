# Claude Code instructions for ICSProject

Read `HANDOVER.md` at repo root before doing substantive work. It documents
the caveats, the pipeline contract, the GUID/asset rules, the perf profile,
and the investigation workflow. The README covers usage; HANDOVER covers
what only experience teaches.

## Quick orientation

- **Product**: the augmented Neo4j Cypher graph emitted by
  `python3 -m network_aug ...`. Downstream invariant mining and the GECO
  detector are optional analytics, not the headline.
- **End use**: LLM-driven investigation from
  `paper_graphs_v2/experiments/investigation_prompt_v3.md` against the
  loaded graph, scored by `paper_graphs_v2/experiments/evaluate.py`
  against hand-curated `*_gt.yaml` ground truth.
- **Canonical asset inventory**: `ICSGraph/Collection/assets.yaml` (do not
  create a sibling `assets.yaml` at repo root — there used to be one and
  it was stale).
- **Smoke test on a new machine**: `pytest tests/`.

## Rules of the road

- The four-stage pipeline (build base graph → augment → optional
  protocol DBs → optional invariants) is documented in HANDOVER.md §2 as
  bare `python3 -m` invocations. The `scripts/run_*.sh` wrappers are
  reference, not requirements — feature the bare commands when teaching
  the pipeline.
- `TMPDIR` must point at real disk (not tmpfs) for any streaming run.
  See HANDOVER §3.6.
- `--force-rebuild` on the PCAP cache whenever inputs change — caches
  have no provenance metadata. See HANDOVER §3.3.
- The default thresholds in `watch_augmentation.sh` SIGTERM healthy 24h+
  runs. Override per HANDOVER §3.12.
- Producers emit GUIDs that match the graph; do not re-introduce a
  post-hoc GUID-fix step for new DBs. The `scripts/fix_signal_guids*.py`
  tools exist only for legacy DBs. See HANDOVER §3.11.
- GECO produces 0 alerts on Industroyer / Triton / FrostyGoop for
  *structural* reasons (constant registers, unit_id namespace
  disjointness). Not a detector bug. See HANDOVER §3.8.

## Editing and committing

- Prefer editing existing files over creating new ones.
- Don't introduce wrapper scripts that duplicate `python -m network_aug`
  semantics — teach the module invocation instead.
- `raw_logs_v0/`, `.scratch_profile/`, `paper_graphs*/` and most large
  binary artifacts are intentionally `.gitignore`d. Don't try to commit
  them.
- Don't commit changes without an explicit ask.
