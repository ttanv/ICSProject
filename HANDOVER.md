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
creates `network_aug_spool_*` directories with one pickle per connection
(~100k files for a 24h Stuxnet run). Without `TMPDIR=$OUT_DIR/tmp`, the spool
eats all RAM and the kernel OOM-kills the process. **Every canonical script
sets `TMPDIR` per-stage; preserve that habit.**

Stale spools persist after a crash. Sweep them with `rm -rf
/tmp/network_aug_spool_*` between runs.

### 3.7 Watch memory

The Modbus group materialization phase peaks 49–60 GB RAM on Stuxnet at
about 32% progress. If you are running multiple datasets in parallel, plan
accordingly. `watch_augmentation.sh <pid> <label>` is the kill-switch
script. Defaults (override via env): `MAX_RSS_KB=12 GiB`,
`MIN_AVAILABLE_KB=20 GiB`, `MAX_SWAP_USED_KB=1 GiB`,
`MAX_RSS_JUMP_KB=1.5 GiB`, polled every 10 s. If any threshold trips, it
SIGTERMs (then SIGKILLs) the target. Logs go to `logs/<label>_watch_<ts>.log`.

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
  streaming_augmentor.py        --streaming path
  streaming.py                  Streaming PCAP loop (dpkt-only)
  missing_augmentor.py          Batch (non-streaming) augmentor
  correlation.py                Telemetry ↔ PCAP correlation
  cypher_emit.py                Cypher writer
  pcap_index*.py                Index builders (dpkt + scapy variants)
  modbus_helpers.py             register_type_from_function, signal keys
  mqtt_helpers.py / opcua_helpers.py
  protocol_signal_db.py         DuckDB schema for signal observations
  protocol_signal_extractors.py Standalone MQTT/OPC UA extraction
  signal_db.py                  Modbus signal DuckDB
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
  compare_streaming_batch.py

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
4. Run the script. Watch with `bash watch_augmentation.sh <pid> <slug>` in
   another shell.
5. Sanity-check before GECO/invariants: `COUNT(DISTINCT value)` per
   register, agreement between telemetry/attack `unit_id`, train/score
   window disjointness. (No GUID-fix step — see 3.11; producers now emit
   the same recipe the graph uses.)
6. Import the augmented graph: `bash purge_db.sh $AUG_CYPHER`.

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

---

## 8. Where to look first when something breaks

| Symptom                                                       | Most likely cause                                                  |
| ---                                                           | ---                                                                |
| 0 successful PCAP→telemetry correlations                      | Wrong `--pcap-time-offset` sign (3.2) or stale cache (3.3).        |
| Graph has no 192.168.0.x evidence                             | `assets.yaml` missing FT hosts (3.1).                              |
| Augmentor OOM-killed                                          | `TMPDIR` not set; `/tmp` is tmpfs (3.6).                           |
| GECO produces 0 alerts on a dataset                           | Constant registers, unit_id mismatch, or same train/score (3.8).   |
| GECO produces alerts with `peak_cusum=0.00`                   | `templates.py` zero-threshold artifact (3.8, item 1).              |
| MQTT/Modbus invariants reference signals not in graph         | Old DB built before the source fix — backfill via fix scripts (3.11). |
| `NetworkService` port mismatch in OPC UA attribution          | String-vs-int port type (3.10).                                    |
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
