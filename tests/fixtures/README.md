# GUID parity fixture (BlackEnergy 1hr)

Verifies that the source-level fix to producer GUID generation is equivalent
to the previous run-then-fix-script flow.

## Why this exists

`scripts/fix_signal_guids_ctas.py` and `scripts/fix_mqtt_signal_guids_ctas.py`
were post-hoc fixups for a producer bug: the Modbus and MQTT signal databases
were being written with `signal_container_guid` / `signal_guid` columns
populated by the **wrong** GUID recipe, so they did not match the
`ICSSignal.guid` values in the augmented cypher graph.

The fix is at source (see `network_aug/protocol_signal_extractors.py` and
`network_aug/missing_augmentor.py`). This fixture confirms the source fix
produces DBs equivalent to running the legacy fix scripts on the old (buggy)
producer output.

## Inputs (read-only, never modified)

- PCAPs: `pcap_traffic/extracted_1hr/BlackEnergy (2015 Ukraine Electric Power Attack)/`
- Logs:  `logs/extracted_1hr/BlackEnergy (2015 Ukraine Electric Power Attack)/`
- Pre-fix raw producer output (from before the fix scripts were applied):
  `paper_graphs_1hr/BlackEnergy/BlackEnergy_*.duckdb.bak`
- Augmented graph cypher:
  `paper_graphs_1hr/BlackEnergy/augmented_BlackEnergy.cypher`

## Layout

```
tests/fixtures/
  run_blackenergy_1hr_sandbox.sh   # produces source-fixed candidate
  check_guid_parity.py             # compares reference vs candidate
  guid_parity_sandbox/             # gitignored
    step1_script_fixed/            # reference: .bak + fix scripts applied
    step4_source_fixed/            # candidate: pipeline run on fixed source
```

## Reproducing the test

```bash
# 1. Reference: copy raw producer .bak files and apply the legacy fix scripts.
mkdir -p tests/fixtures/guid_parity_sandbox/step1_script_fixed
cp paper_graphs_1hr/BlackEnergy/BlackEnergy_signals.duckdb.bak \
   tests/fixtures/guid_parity_sandbox/step1_script_fixed/BlackEnergy_signals.duckdb
cp paper_graphs_1hr/BlackEnergy/BlackEnergy_mqtt_signals.duckdb.bak \
   tests/fixtures/guid_parity_sandbox/step1_script_fixed/BlackEnergy_mqtt_signals.duckdb

python3 scripts/fix_signal_guids_ctas.py \
  paper_graphs_1hr/BlackEnergy/augmented_BlackEnergy.cypher \
  tests/fixtures/guid_parity_sandbox/step1_script_fixed/BlackEnergy_signals.duckdb

python3 scripts/fix_mqtt_signal_guids_ctas.py \
  paper_graphs_1hr/BlackEnergy/augmented_BlackEnergy.cypher \
  tests/fixtures/guid_parity_sandbox/step1_script_fixed/BlackEnergy_mqtt_signals.duckdb

# 2. Candidate: run the pipeline on source-fixed code into a fresh sandbox.
tests/fixtures/run_blackenergy_1hr_sandbox.sh

# 3. Verify equivalence.
python3 tests/fixtures/check_guid_parity.py
```

## Bug witness (run *before* applying the source fix)

To confirm the producer bug actually reproduces with this fixture:

```python
import duckdb, re
from pathlib import Path
cypher = Path("paper_graphs_1hr/BlackEnergy/augmented_BlackEnergy.cypher")
graph_modbus, graph_mqtt = set(), set()
KEY = re.compile(r"signalKey: '([^']+)'")
GUID = re.compile(r"guid: '(\{[^}]+\})'")
for line in cypher.open():
    k, g = KEY.search(line), GUID.search(line)
    if not (k and g): continue
    sk = k.group(1)
    if sk.startswith("modbus|"): graph_modbus.add(g.group(1))
    elif sk.startswith("mqtt|"): graph_mqtt.add(g.group(1))
for name, col, ref in [
    ("BlackEnergy_signals.duckdb.bak",      "signal_container_guid", graph_modbus),
    ("BlackEnergy_mqtt_signals.duckdb.bak", "signal_guid",           graph_mqtt),
]:
    con = duckdb.connect(f"paper_graphs_1hr/BlackEnergy/{name}", read_only=True)
    db = {r[0] for r in con.execute(f"SELECT DISTINCT {col} FROM signal_observations").fetchall()}
    print(f"{name}: db={len(db)} graph={len(ref)} intersect={len(db & ref)}")
```

Expected output (reproduced 2026-05-10):

```
BlackEnergy_signals.duckdb.bak:      db=3  graph=17 intersect=0
BlackEnergy_mqtt_signals.duckdb.bak: db=18 graph=18 intersect=0
```

`intersect=0` confirms the bug.
