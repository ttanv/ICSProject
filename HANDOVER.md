# HANDOVER

A practical guide for picking up this repo. Caveats first, mechanics second.
The README explains *what* the tool does and *how* to invoke it; this document
covers the things you only learn after running into them.

---

## 1. What this repo actually is

A pipeline that takes:

- a **base Cypher graph** built from Sysmon/ETW host telemetry
  (`ICSGraph/Collection/build_graph.py`), plus
- **PCAPs** of the same time window,

and emits an **augmented Cypher graph** plus optional **DuckDB signal stores**
(Modbus/MQTT/OPC UA). The augmented graph is imported into Neo4j; the DuckDBs
feed two downstream analytics paths: invariant mining (`network_aug.invariants`,
`invariantExperiments.extract_*_invariants`) and the GECO CUSUM detector
(`network_aug.geco`, `network_aug.geco_opcua`).

Two testbeds are mixed in most datasets: a Tennessee Eastman simulation
(192.168.43.x / 192.168.44.x, Modbus on 502) and a FischerTechnik physical rig
(192.168.0.x, S7 on 102 and OPC UA on 4840). FrostyGoop is the only scenario
that is pure-TEP. See `memory/project_testbeds.md` for the full mapping.

---

## 2. Canonical pipeline (the order matters)

The reference implementation lives in `scripts/run_industroyer_24h_v2.sh`
(also `run_pipedream_24h_v1.sh`, `run_fuxnet_newversion_1hr_v1.sh`,
`run_industroyer_1hr_safe_db.sh`, `run_1hr_batch_extract.sh`). For a new
dataset, copy one of those and adjust paths. The four stages:

1. **Build base graph** from Sysmon logs:
   ```
   TMPDIR=$OUT_DIR/tmp python3 ICSGraph/Collection/build_graph.py \
     --logs $LOG_DIR --assets $ASSETS --output $BASE_CYPHER --workers 8
   ```

2. **Augment** with PCAP evidence and write the Modbus signal DB:
   ```
   TMPDIR=$OUT_DIR/tmp python3 -m network_aug \
     --base-cypher $BASE_CYPHER --output-cypher $AUG_CYPHER \
     --pcap-dir $PCAP_DIR --assets $ASSETS \
     --cache $CACHE --force-rebuild \
     --streaming --signal-db $MAIN_DB
   ```

3. **MQTT/OPC UA standalone extraction** (separate from main pipeline by
   design — streaming augmentor does not produce MQTT/OPC UA `ICSSignal`
   artifacts):
   ```
   TMPDIR=$OUT_DIR/tmp python3 -m invariantExperiments.extract_protocol_signals \
     $PCAP_DIR --mqtt-db $MQTT_DB --opcua-db $OPCUA_DB \
     --assets $ASSETS --cache $PROTOCOL_CACHE --force-rebuild
   ```

4. **Mine invariants** (Modbus shown; MQTT/OPC UA have parallel modules):
   ```
   TMPDIR=$OUT_DIR/tmp python3 -m network_aug.invariants \
     --signal-db $MAIN_DB --output $INVARIANTS_JSON
   ```

Then optionally train/score GECO (`network_aug.geco` for Modbus,
`network_aug.geco_opcua` for OPC UA). Use **disjoint** baseline and scoring
windows (or two separate DuckDB files); training and scoring on the same
window will produce 0 alerts by construction.

Importing the augmented Cypher into Neo4j is done by `purge_db.sh
<file.cypher>` — it stops Neo4j, wipes
`/var/lib/neo4j/data/{transactions,databases}/neo4j`, restarts, and pipes the
file into `cypher-shell`. Default credentials are baked in
(`neo4j` / `icsproject`).

---

## 3. Critical caveats

### 3.1 `assets.yaml` must list every host in scope

`ICSGraph/Collection/assets.yaml` must include all 192.168.0.x FischerTechnik
hosts as well as the supervisory side. Missing entries cause:

- traffic to fall back to `runtime://<ip>` placeholders,
- silent loss of process attribution,
- strange labelling (e.g. 192.168.0.12 mistakenly tied to a firewall).

Conversely, **`has_logs: true` blocks placeholder-process creation** — the
streaming augmentor will refuse to synthesize a virtual `runtime://` process
for a host marked as logged, which means PCAP-only outgoing connections from
that host are dropped. If you want a virtual process for a logless host
(e.g. DMZ-LINUX-01), set `has_logs: false`.

If a graph is missing 192.168.0.x evidence entirely, the assets file is
almost certainly the cause.

### 3.2 PCAP timezone alignment

PCAPs in some datasets are recorded in UTC+3 (Qatar) while telemetry is UTC.
Running without an offset zeroes correlation scores in
`network_aug/correlation.py` because the time windows do not overlap. Pass:

```
--pcap-time-offset -3
```

(in hours). The default is `0.0`. Wrong sign ⇒ zero successful correlations.

### 3.3 Always `--force-rebuild` when the PCAP set changes

`pcap_connection_index.pkl` (or per-dataset cache files) carry no provenance
metadata. If the cache was built from a different PCAP set, the augmenter
silently builds a graph from the old packets. There is no validation. The
canonical scripts always pass `--force-rebuild`; do the same unless you are
deliberately re-using a cache for the same input directory.

### 3.4 `--streaming` ≠ `--no streaming`

- Streaming hardcodes the `dpkt` parser and ignores `USE_SCAPY_PARSER=1`.
- Streaming and batch produce slightly different GUIDs because of host vs.
  IP resolution differences in Modbus signal keys. This is structural, not
  a bug.
- In older versions, streaming silently dropped MQTT/OPC UA `ICSSignal`
  artifacts. Stage 3 of the canonical pipeline (`extract_protocol_signals`)
  exists to fill that gap and is intentionally separate.
- A corrupt PCAP aborts the whole streaming run (`network_aug/streaming.py`
  raises `RuntimeError` on scapy fallback). Move the broken file aside
  (e.g. into a `_broken/` subdir) and rerun rather than chasing the error.

### 3.5 Do not parallelize jobs against the same paths

Two concurrent augmentations pointing at the same `--cache`, `--output-cypher`,
or `--signal-db` will corrupt each other. The 1hr batch script
(`run_1hr_batch_extract.sh`) parallelizes by **dataset slug**, with
per-dataset paths.

### 3.6 `TMPDIR` must point at real disk

`/tmp` on this host is tmpfs (RAM-backed, ~32 GB). The streaming augmentor
creates three different temp-dir trees on disk:

- `network_aug_spool_*` — one pickle per candidate connection (~100k
  files / ~30 GB for a 24h run, ~210 GB for a 1-week run).
- `network_aug_stats_shards_*` — one pickle per PCAP with all of its
  `ConnectionStats` (added by the per-PCAP stats spill; ~250 MB per
  PCAP-hour; deleted after candidate selection).
- `network_aug_modbus_shards_*` — one Parquet per PCAP with all
  fully-resolved Modbus observations (deleted after the bulk-load into
  DuckDB).

Without `TMPDIR=$OUT_DIR/tmp`, the spool + shards eat all RAM and the
kernel OOM-kills the process. **Every canonical script sets `TMPDIR`
per-stage; preserve that habit.**

Stale dirs persist after a crash. Sweep them with:

```bash
rm -rf "$TMPDIR"/network_aug_spool_* \
       "$TMPDIR"/network_aug_stats_shards_* \
       "$TMPDIR"/network_aug_modbus_shards_*
```

### 3.7 Watch memory

The default `watch_augmentation.sh` thresholds (`MAX_RSS_KB=12 GiB`,
`MIN_AVAILABLE_KB=20 GiB`, `MAX_SWAP_USED_KB=1 GiB`,
`MAX_RSS_JUMP_KB=1.5 GiB`, polled every 10 s) **are too tight for the
24h+ streaming runs after the Apr 2026 optimizations**. They were sized
for the pre-optimization batch augmentor where the Modbus group
materialization phase peaked 49–60 GB on Stuxnet at ~32% progress.

The streaming pipeline now hits ~25 GB peak on BE 24h and ~35 GB on
Stuxnet 24h. See §3.12 for measured numbers and recommended override
flags. If you are running the legacy batch path (`MissingTrafficAugmentor`
without `--streaming`), the old 49–60 GB profile still applies.

For Modbus parallelism inside one run: `NETWORK_AUG_MODBUS_WORKERS`
(defaults `min(8, cpu-1)`); set to `1` to disable. The `signal_container_guid`
scoping change (commit `de21558`) prevents cross-server register conflation
but produces fat groups that don't always parallelize well.

### 3.8 GECO results need a sanity check before you trust them

The GECO detector itself is correct (`tests/test_geco.py`). Three failure
modes are not:

1. **Constant-during-training signals → spurious alerts.**
   `network_aug/geco/templates.py` floors `drift` at 1e-9 and sets
   `threshold = max(threshold, drift)`. A register that never changed during
   training gets `trigger_threshold ≈ 1.5e-9`; any single value flip during
   scoring fires `peak_cusum=0.00, max_abs_error=1.0`. Open defect — see
   `memory/project_geco_dataset_limits.md`. Mitigation: skip templates with
   `max(y) - min(y) < eps` during training.
2. **Attacks on a different `unit_id` than the modeled telemetry → 0 real
   alerts.** Candidate predictor search in
   `network_aug/geco/dataset.py:271` groups by `(server_host, unit_id)`.
   FrostyGoop's attack writes are on `unit_id=1` while telemetry models are
   trained on `unit_id=247`. The two namespaces never couple. This is not a
   detector bug; it is a structural limit.
3. **Constant registers → CUSUM never accumulates.** Industroyer (12/13
   models trivial) and Triton (TriStation native; only Modbus shadow) sit
   in this hole.

Before declaring "GECO works/doesn't work" on a new dataset, check:
- baseline registers have `COUNT(DISTINCT value) > 1`;
- attack and telemetry share the same `unit_id`;
- attack window is long enough for CUSUM to accumulate past the threshold;
- train and score windows are **disjoint** (use `--baseline-hours` or two
  separate DuckDBs).

`TEMPLATE_AFFINE` and `TEMPLATE_AFFINE_INTERACTION` are identical when
`subset_len=0` — double-fits. Cosmetic but worth knowing if you compare
template counts.

### 3.9 Modbus address-space conflation (semi-fixed)

Coil / discrete-input / input-register / holding-register share numeric
address ranges. An older bug created one Register node per
`(host, port, address, unit_id)` regardless of register type. Fix is in
`network_aug/missing_augmentor.py` (around lines 1398 and 2280) but
**existing imported Neo4j data stays conflated until augmentation is
regenerated and re-imported.** Re-augment from PCAPs whenever in doubt.

### 3.10 Other pre-existing-edge gotchas

- Edges with `correlatedFromBinds=true` are attribution by listener
  ownership, not proven outbound init. Don't treat them like real
  telemetry-confirmed connections.
- `NetworkService.port` may be a string (`"4840"`) in some Sysmon-derived
  base nodes while PCAP code uses int `4840`. Type mismatch silently forces
  temporal-only attribution for OPC UA.
- `runtime://8` in graphs is `runtime://8.8.8.8` truncated by a downstream
  regex, not a parse bug.

### 3.11 Legacy DBs need GUID backfill (new producers do not)

Historically the Modbus / MQTT signal DBs shipped with `signal_container_guid`
/ `signal_guid` values that did not match the augmented graph's
`ICSSignal.guid`. Producers in `network_aug/missing_augmentor.py`
(`_record_observation`) and `network_aug/protocol_signal_extractors.py`
(MQTT batch + streaming paths) now compute the same GUID recipe as the graph
builder, so freshly produced DBs join cleanly without any post-processing.

The `scripts/fix_signal_guids_ctas.py` (Modbus) and
`scripts/fix_mqtt_signal_guids_ctas.py` (MQTT) tools are still checked in as
**one-shot backfills** for DBs created before the fix — most `paper_graphs*`
artifacts in this repo were rewritten by them, with `.preCTAS` and `.bak`
suffixes preserving the pre-fix state. Do not run them as part of new
pipeline runs; they are no-ops on correctly-produced DBs.

Regression check: `tests/fixtures/run_blackenergy_1hr_sandbox.sh` plus
`tests/fixtures/check_guid_parity.py` runs the BlackEnergy 1hr pipeline into
a sandbox and asserts the producer output is equivalent (same row count,
same distinct GUID set, same per-natural-key GUID map, same content hash on
identity-bearing columns) to the legacy "run + apply fix script" flow. See
`tests/fixtures/README.md` for how to reproduce.

`scripts/fix_signal_guids.py` (UPDATE-based, slow) is kept only for tiny
DBs; the CTAS variants supersede it on anything bigger.

### 3.12 Performance and memory at scale (post-Apr 2026)

Two commits on `simplify-correlation` substantially cut wall time and
peak RSS for the streaming augmentor. The wins compound with capture
length, so multi-day runs are now feasible on a 64 GB box.

- `0e26f5c` — DuckDB index deferral on `signal_observations` (drop at
  ingest, rebuild on close), bulk write-acks via a staging table +
  single `UPDATE FROM`, and inline Modbus signal extraction in pass-1
  workers via per-PCAP Parquet shards bulk-loaded after pass 1. The
  legacy apply-time `_collect_modbus_signals` loop is short-circuited
  when shards are preloaded.
- `f65c337` — per-PCAP `ConnectionStats` spill (`configure_stats_spill`
  in `StreamingPCAPIndex`) replaces the in-memory `stats_by_cid` dict.
  `_augment_existing_relationships` consumes packets via `heapq.merge`
  over the per-correlation spooled iterators and folds them through
  a `RelationshipFeatureAccumulator` in `features.py`. Both kill the
  linear-growth memory terms that previously blocked 1-week+ runs.

**Measured baseline — BlackEnergy 24h** (39 PCAPs, 19 GB, 90.9M packets):

| Stage | Wall | RSS at exit |
| --- | ---: | ---: |
| Pass 1 (parse + stats + inline Modbus extract) | 35 min | 0.6 GB |
| Pass 2 (materialize candidate spool) | 27 min | 2.5 GB |
| Build artifacts (graph emission) | 23 min | 16.1 GB |
| **Total wall** | **~85 min** | |
| **Peak RSS (background sampler)** | | **25.9 GB** |

The ~10 GB gap between final stage RSS (16.1 GB) and the sampled peak
(25.9 GB) is **DuckDB's index rebuild at `close()`** — 5 indexes on the
27M-row `signal_observations` table. Roughly independent of capture
length once the table exists.

**Estimated wall + peak for the other 24h scenarios** (~290 s/GB of
PCAP, peak governed mostly by index rebuild + per-edge accumulator):

| Scenario | PCAPs | PCAP size | Wall estimate | Peak RSS estimate |
| --- | ---: | ---: | ---: | ---: |
| FrostyGoop | 28 | 14 GB | ~65 min | ~18 GB |
| Triton | 33 | 16 GB | ~75 min | ~20 GB |
| IndustroyerV2 | 33 | 16 GB | ~75 min | ~20 GB |
| **BlackEnergy ✓** | **39** | **19 GB** | **85 min** | **25.9 GB** |
| Fuxnet | 44 | 21 GB | ~95 min | ~22 GB |
| Industroyer | 46 | 23 GB | ~105 min | ~24 GB |
| Pipedream | 67 | 33 GB | ~2 h 30 m | ~30 GB |
| Stuxnet | 97 | 47 GB | ~3 h 30 m | ~35 GB |

1-week extrapolation: wall ~10 h, peak ~20–25 GB. The two linear-growth
terms are gone; what's left scales with observation count (DuckDB index
build) which is ~7× the 24h size, still well under 64 GB.

**Watch-script thresholds** — the defaults in `watch_augmentation.sh`
(`MAX_RSS_KB=12 GiB`, `MIN_AVAILABLE_KB=20 GiB`) trip during normal
operation on these workloads. Recommended overrides for 24h+ runs:

```bash
MAX_RSS_KB=$((40 * 1024 * 1024)) \
MIN_AVAILABLE_KB=$((8 * 1024 * 1024)) \
MAX_RSS_JUMP_KB=$((5 * 1024 * 1024)) \
bash watch_augmentation.sh "$pid" "$slug"
```

(40 GB RSS ceiling, 8 GB minimum free system memory, 5 GB allowed
single-poll jump for the index-rebuild transient.)

**Spool / shard directories** — beyond the old `network_aug_spool_*`,
the new code creates two more temporary dirs (all under `$TMPDIR`):

- `network_aug_stats_shards_*` — per-PCAP `ConnectionStats` pickles,
  ~250 MB per PCAP-hour. Cleaned up after candidate selection.
- `network_aug_modbus_shards_*` — per-PCAP Parquet shards with
  fully-resolved Modbus observations. Cleaned up after bulk-load.

If a run crashes mid-way, sweep all three from `$TMPDIR`:

```bash
rm -rf "$TMPDIR"/network_aug_spool_* \
       "$TMPDIR"/network_aug_stats_shards_* \
       "$TMPDIR"/network_aug_modbus_shards_*
```

**Profiling new workloads** — `python -m tests.profile_streaming_aug
--base-cypher … --pcap-dir … --assets … --signal-db … --output stats.json`
runs the full streaming pipeline with non-invasive monkey-patching that
captures per-stage wall time, RSS in/out at each stage boundary, peak
RSS via a 0.5 s background sampler, and DuckDB hot-path call counts.
Output is a JSON file plus a console table. Use it any time you suspect
a regression or new bottleneck — the numbers in this section came from
exactly this tool.

---

## 4. Dataset-specific quirks

These are non-obvious facts about the bundled scenarios:

- **FrostyGoop** is pure-TEP — no 192.168.0.x traffic. If your graph shows
  FT-side evidence for FrostyGoop, something is wrong upstream.
- **Industroyer / Triton** Modbus signals are essentially constant — ground
  truth is "0 real alerts" for structural reasons, not a detector bug.
- **Stuxnet's `logs/extracted/Stuxnet/` was duplicated from Pipedream** in
  earlier dataset prep. Some "Stuxnet" results are really Pipedream's.
  Re-extract before trusting older paper graphs.
- **`paper_graphs/Pipedream_signals.duckdb` and `Stuxnet_signals.duckdb`
  may be empty** in older runs. Verify with
  `SELECT COUNT(*) FROM signal_observations` before training GECO on them.
- **BlackEnergy MQTT** has the broker-name mismatch (FT-MQTT-01 vs
  FT-HMI-01); use the CTAS fix script.
- **FT-testbed PCAPs contain ~63k of 200k byte-identical duplicate frames**
  from the SPAN/port-mirror. MQTT 2.0× duplicated, OPC UA ~1.5×, Modbus 0×.
  This inflates `obs_count`, `pair_count`, and confidence scores; biases
  GECO thresholds low. Pearson correlations are dedup-invariant.
- **Encrypted MQTT (8883) and OPC UA SignAndEncrypt** yield only metadata —
  no Read/Write NodeId extraction.
- **Modbus PCAP only shows client requests + server responses**, never the
  PLC's internal sensor-driven writes. Don't infer "process wrote register"
  from Modbus alone.
- **`BlackEnergy.zip` in the project root is corrupt/truncated (~5 MB).**
  Re-download.
- Identical `192.168.0.1` traffic byte counts across multiple scenarios
  (e.g. Stuxnet vs Pipedream) are not cross-contamination — the same
  supervisory testbed was re-used.

---

## 5. Layout and where things live

```
network_aug/                    Augmentation engine
  __main__.py                   CLI entry
  enhancer.py                   AugmentationConfig + main batch flow
  streaming_augmentor.py        --streaming path; per-PCAP stats spill
  streaming.py                  Streaming PCAP loop + ConnectionStats
                                shard machinery (configure_stats_spill,
                                iter_shards, iter_merged_stats)
  streaming_modbus_extract.py   Inline Modbus signal extractor used by
                                pass-1 workers (writes Parquet shards)
  missing_augmentor.py          Batch (non-streaming) augmentor;
                                _augment_existing_relationships now
                                streams via heapq.merge
  features.py                   RelationshipFeatureAccumulator
                                (streaming feature extractor) +
                                legacy list-based extractors
  correlation.py                Telemetry ↔ PCAP correlation
  cypher_emit.py                Cypher writer
  pcap_index*.py                Index builders (dpkt + scapy variants)
  modbus_helpers.py             register_type_from_function, signal keys
  mqtt_helpers.py / opcua_helpers.py
  protocol_signal_db.py         DuckDB schema for signal observations
  protocol_signal_extractors.py Standalone MQTT/OPC UA extraction
  signal_db.py                  Modbus signal DuckDB; index deferral
                                + bulk write-ack staging table
  geco/                         Modbus GECO detector (train/score)
  geco_opcua/                   OPC UA GECO detector
  invariants/                   Modbus invariant miner

invariantExperiments/           Standalone collectors and miners
  extract_signals.py            Modbus collector
  extract_protocol_signals.py   MQTT + OPC UA collector
  extract_mqtt_invariants.py    MQTT invariants
  extract_opcua_invariants.py   OPC UA invariants
  validate_invariants.py
  dedupe_signal_db.py
  simplified_te.st              ST source for state-aware enrichment

ICSGraph/Collection/            Telemetry → base graph
  build_graph.py
  assets.yaml                   *** KEEP THIS UP TO DATE ***

scripts/                        Orchestration + one-off fixes
  run_*.sh                      Per-dataset pipelines (templates)
  fix_signal_guids_ctas.py      Legacy Modbus DB GUID backfill (CTAS) — see 3.11
  fix_signal_guids.py           Legacy Modbus DB GUID backfill (UPDATE; small DBs only)
  fix_mqtt_signal_guids_ctas.py Legacy MQTT DB GUID backfill — see 3.11

tests/                          pytest
  test_geco.py / test_geco_opcua.py
  test_invariants.py / test_mqtt_invariants.py / test_opcua_invariants.py
  test_protocol_signal_extraction.py
  test_streaming_parity.py      Streaming vs batch comparison
  test_stats_spill.py           Per-PCAP shard merge equals in-memory merge
  test_streaming_features.py    Streaming feature accumulator parity
  compare_streaming_batch.py
  profile_streaming_aug.py      Non-invasive per-stage profiler — see §3.12

docs/
  architecture-overview.md      Read first, this is the canonical doc
  register_summarization_analysis.md
  forensic_analysis_prompt_arch{1,2}_v{1,2,3}.md
  prompts/story-reconstruction-prompts.md

memory/                         Auto-memory used by Claude Code (not source)
  MEMORY.md
  project_testbeds.md           Useful — testbed split per scenario
  project_geco_dataset_limits.md  Useful — why GECO produces 0 alerts on 3 datasets

watch_augmentation.sh           Kill-switch for runaway runs
purge_db.sh                     Wipe + re-import Neo4j from a Cypher file
augmentation_log.txt            Shared log of past runs (append-only history)
```

---

## 6. Quick-start checklist for a new dataset

1. Add every host that appears in PCAPs to `ICSGraph/Collection/assets.yaml`
   (especially 192.168.0.x). Decide `has_logs` per host.
2. Copy `scripts/run_pipedream_24h_v1.sh` → adjust `SLUG`, `LOG_DIR`,
   `PCAP_DIR`, `OUT_DIR`. Keep the per-dataset `TMP_DIR`.
3. If PCAPs are not in UTC, add `--pcap-time-offset <hours>` to the
   `network_aug` invocation.
4. Estimate wall + peak from §3.12 and pick a `TMPDIR` with enough disk
   for the spool. Raise `watch_augmentation.sh` thresholds per §3.12 if
   running a 24h+ scenario — the defaults will SIGTERM a healthy run.
5. Run the script. Watch with `bash watch_augmentation.sh <pid> <slug>` in
   another shell (with the overrides from §3.12).
6. Sanity-check before GECO/invariants: `COUNT(DISTINCT value)` per
   register, agreement between telemetry/attack `unit_id`, train/score
   window disjointness. (No GUID-fix step — see 3.11; producers now emit
   the same recipe the graph uses.)
7. Import the augmented graph: `bash purge_db.sh $AUG_CYPHER`.

For one-off profiling or regression hunts, prefer
`python -m tests.profile_streaming_aug ...` over the canonical script —
it captures per-stage wall time + peak RSS into a JSON file with no
source modifications. See §3.12 for invocation.

---

## 7. Open defects worth fixing early

- `network_aug/geco/templates.py` zero-threshold artifact (3.8 above).
  Spurious low-cusum alerts on constant registers.
- GECO candidate search is within-`(server_host, unit_id)` only — no
  cross-unit correlations. FrostyGoop is the canonical case where this
  matters.
- `--streaming` ignores `USE_SCAPY_PARSER`; document or wire it through.
- `streaming.py` aborts on a single corrupt PCAP instead of skipping.
- Cache files have no provenance metadata; users have to remember
  `--force-rebuild`. A cache header with PCAP-set hash would prevent silent
  wrong-graph runs.
- `scripts/run_*.sh` use `set -uo pipefail` but **not** `set -e`.
  Mid-pipeline failures don't abort the wrapper. Adding `-e` (or per-stage
  exit checks) would prevent downstream stages running on bad inputs.
- DuckDB index rebuild at `SignalDatabase.close()` adds a ~10 GB
  transient peak on 24h runs (~15 GB at 1 week), independent of the
  caller's working set. Building indexes sequentially (`for name, defn in
  INDEX_DEFS: conn.execute(...)`) instead of inside the same try-block
  would cap the transient at one index's working memory. See §3.12 for
  measured numbers.
- The streaming inline-Modbus extractor in `streaming_modbus_extract.py`
  applies asset-IP scope filtering but not the `is_broadcast/is_outer/in_base_graph`
  filters the legacy per-group extractor used. Result: signal DB now
  contains ~5–25 % more rows than the legacy path (verified strict
  superset on BE 24h and Pipedream 1hr). Net effect is more downstream
  coverage, not duplicates. Port the filters into the extractor if you
  need byte-exact parity with older `paper_graphs/*` outputs.

---

## 8. Where to look first when something breaks

| Symptom                                                       | Most likely cause                                                  |
| ---                                                           | ---                                                                |
| 0 successful PCAP→telemetry correlations                      | Wrong `--pcap-time-offset` sign (3.2) or stale cache (3.3).        |
| Graph has no 192.168.0.x evidence                             | `assets.yaml` missing FT hosts (3.1).                              |
| Augmentor OOM-killed                                          | `TMPDIR` not set; `/tmp` is tmpfs (3.6).                           |
| `watch_augmentation.sh` kills a healthy 24h+ run              | Default kill thresholds sized for legacy batch path (3.7); raise per §3.12. |
| GECO produces 0 alerts on a dataset                           | Constant registers, unit_id mismatch, or same train/score (3.8).   |
| GECO produces alerts with `peak_cusum=0.00`                   | `templates.py` zero-threshold artifact (3.8, item 1).              |
| MQTT/Modbus invariants reference signals not in graph         | Old DB built before the source fix — backfill via fix scripts (3.11). |
| `NetworkService` port mismatch in OPC UA attribution          | String-vs-int port type (3.10).                                    |
| New signal DB has ~10% more rows than old `paper_graphs/*`    | Inline Modbus extractor lacks legacy group-level filters (§7 open defect). Not a regression — strict superset. |
| Two scenarios show byte-identical 192.168.0.1 traffic         | Same shared supervisory testbed, not contamination.                |
| Streaming run died on one PCAP                                | Corrupt file; move it aside and rerun (3.4).                       |
| `BrokenProcessPool` / exit 137 from protocol extractor        | Multiple workers writing one DuckDB; serialize or use per-worker dbs. |

---

## 9. Conventions in past runs

- One output directory per dataset — `paper_graphs/`, `paper_graphs_v0/`,
  `_v1/`, `_v2/`, `paper_graphs_1hr/`, `paper_graphs_parallel/` are
  successive iterations of the same scenarios with different time slices /
  pipeline versions. The `_v2` series is the most recent.
- Per-dataset DB filenames follow `<Slug>_signals.duckdb`,
  `<Slug>_mqtt_signals.duckdb`, `<Slug>_opcua_signals.duckdb`.
- Backup suffixes used by scripts: `.partial_<timestamp>` for pre-stage
  rollovers, `.preCTAS` for pre-fix DBs, `.bak` for the original collector
  output. Originals are preserved; nothing is destroyed in place.
- All run scripts include a `verify_db()` Python heredoc that confirms each
  DuckDB has a non-zero `signal_observations` row count before declaring
  success. Keep that pattern in new scripts.
