# Invariant Violation Validation

Use `validate_invariants.py` to check benign invariants against an attack-period
signal DuckDB and produce a clean list of violations.

## Command

Run from the repository root:

```bash
python -m invariantExperiments.validate_invariants \
  <invariants.json> \
  <attack_signals.duckdb> \
  [output.json]
```

Examples:

```bash
python -m invariantExperiments.validate_invariants \
  experiments/pipe_24h/Pipedream_invariants.json \
  attack_modbus_signals.duckdb \
  pipe_violations.json
```

```bash
python -m invariantExperiments.validate_invariants \
  experiments/pipe_24h/Pipedream_mqtt_invariants.json \
  attack_mqtt_signals.duckdb \
  mqtt_violations.json
```

If `output.json` is omitted, the script prints the report only. If it is
provided, the same structured report is written to that file.

## One File for Multiple Protocols

To validate Modbus, MQTT, and OPC UA invariants in one command, pass each
invariant file with the matching attack signal DuckDB using repeated `--pair`
arguments:

```bash
python -m invariantExperiments.validate_invariants \
  --pair modbus_invariants.json attack_modbus_signals.duckdb \
  --pair mqtt_invariants.json attack_mqtt_signals.duckdb \
  --pair opcua_invariants.json attack_opcua_signals.duckdb \
  --output all_violations.json
```

The output file will contain one combined report. Its top-level `violations`
list includes violations from all pairs, sorted by first violation time when a
timestamp is available. Each violation also includes a `source` field:

```json
{
  "source": {
    "invariants_path": "mqtt_invariants.json",
    "attack_db_path": "attack_mqtt_signals.duckdb"
  }
}
```

Use this form when the protocol signal data is split across separate DuckDBs,
which is the normal layout for this repo.

## Unified SAIN and GECO Alerts

`validate_invariants.py` only creates SAIN-style invariant violations. GECO
already creates its own alert files through `network_aug.geco score` and
`network_aug.geco_opcua score`.

To combine both detector families into one alert file, use
`collect_alerts.py`:

```bash
python -m invariantExperiments.collect_alerts \
  --sain-pair modbus_invariants.json attack_modbus_signals.duckdb \
  --sain-pair mqtt_invariants.json attack_mqtt_signals.duckdb \
  --sain-pair opcua_invariants.json attack_opcua_signals.duckdb \
  --geco-alerts modbus=modbus_geco_alerts.json \
  --geco-alerts opcua=opcua_geco_alerts.json \
  --output unified_alerts.json
```

The GECO protocol prefix is optional when the file already has a `protocol`
field. Modbus GECO files usually do not, so `modbus=...` is recommended.

The unified file has this shape:

```json
{
  "summary": {
    "total_alerts": 2,
    "by_source": {
      "sain": 1,
      "geco": 1
    },
    "by_protocol": {
      "modbus": 2
    },
    "by_type": {
      "value_range": 1,
      "geco_cusum": 1
    }
  },
  "inputs": {
    "sain_pairs": [],
    "geco_alerts": []
  },
  "alerts": []
}
```

Each alert in `alerts` uses the same normalized fields:

```json
{
  "source": "sain",
  "protocol": "modbus",
  "type": "value_range",
  "name": "reg_40001",
  "signal_ids": ["guid@PLC"],
  "start_timestamp": 123.0,
  "end_timestamp": 123.0,
  "severity": "medium",
  "details": {},
  "source_files": {},
  "raw": {}
}
```

GECO alerts use `source: "geco"` and `type: "geco_cusum"`. Their `details`
include `peak_cusum`, `threshold`, `triggered_points`, `max_abs_error`, and
`first_trigger_timestamp`. SAIN alerts keep the invariant violation details,
benign values, attack values, and observation count.

Use `unified_alerts.json` when a downstream report, prompt, or graph import
should consume both SAIN invariant violations and GECO residual/CUSUM alerts.

## Supported Inputs

The script supports invariant JSON files produced by the repo's miners:

- Modbus: `network_aug.invariants`
- MQTT: `invariantExperiments.extract_mqtt_invariants`
- OPC UA: `invariantExperiments.extract_opcua_invariants`

Supported invariant types:

- `value_range`: checks whether attack values leave benign min/max bounds or
  have a large mean shift.
- `inter_register`: checks Modbus register correlation changes.
- `inter_signal`: checks MQTT/OPC UA signal correlation changes.
- `state_transition`: best-effort Modbus check for unexpected state transitions.

## Output

The canonical clean output is:

```python
report["violations"]
```

It is a list of dictionaries. Each violation has this general shape:

```json
{
  "type": "value_range",
  "protocol": "mqtt",
  "name": "factory/sensor.temp",
  "signal_ids": ["guid-temp"],
  "identity": {
    "signal_guid": "guid-temp",
    "server_host": "BROKER",
    "topic": "factory/sensor",
    "field_name": "temp",
    "signal_name": "factory/sensor.temp"
  },
  "violations": {
    "above_max": "59.0 > 30.0"
  },
  "first_violation_time": 1011.0,
  "benign": {
    "min": 20.0,
    "max": 30.0,
    "mean": 25.0,
    "stddev": 1.0
  },
  "attack": {
    "min": 20.0,
    "max": 59.0,
    "mean": 39.5,
    "stddev": 11.6905
  },
  "observation_count": 40
}
```

The report also keeps the older grouped fields:

- `invariants_checked`
- `violations_detected`
- `flat_violations`
- `violation_trees`
- `uncorrelated_violations`
- `skipped_invariants`

Prefer `violations` for new downstream code. Use `flat_violations` only if you
need the older grouped format.

## Violation Kinds

For `value_range`, the nested `violations` object can contain:

- `below_min`
- `above_max`
- `mean_shift`

For `inter_register` and `inter_signal`, it can contain:

- `correlation_drop`
- `slope_change`
- `intercept_shift`

For `state_transition`, it can contain:

- `unexpected_transition`

## Notes

- The script infers protocol from the invariant JSON and DuckDB schema.
- MQTT and OPC UA use `signal_guid`; Modbus uses `signal_container_guid` and can
  also fall back to register/unit lookup.
- Modbus checks use `server_host` when available to avoid mixing signals from
  different devices.
- `state_transition` validation is intentionally best-effort because current
  transition invariants store only simple `from_state -> to_state` expectations.
