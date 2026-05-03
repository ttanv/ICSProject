#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

OUT_DIR="paper_graphs_1hr/Industroyer"
PCAP_DIR="pcap_traffic/extracted_1hr/Industroyer"
ASSETS="ICSGraph/Collection/assets.yaml"
TMP_DIR="$OUT_DIR/tmp"
LOG="$OUT_DIR/Industroyer_safe_db_rerun.log"

BASE_CYPHER="$OUT_DIR/base_Industroyer.cypher"
EXISTING_AUG="$OUT_DIR/augmented_Industroyer.cypher"
RERUN_AUG="$OUT_DIR/augmented_Industroyer.with_db_rerun.cypher"
MAIN_DB="$OUT_DIR/Industroyer_signals.duckdb"
MQTT_DB="$OUT_DIR/Industroyer_mqtt_signals.duckdb"
OPCUA_DB="$OUT_DIR/Industroyer_opcua_signals.duckdb"
CACHE="$OUT_DIR/Industroyer_safe_pcap_index.pkl"

log() {
  printf '[%s] %s\n' "$(date -Is)" "$*"
}

backup_if_exists() {
  local path="$1"
  if [[ -e "$path" ]]; then
    mv "$path" "${path}.partial_$(date +%Y%m%d_%H%M%S)"
  fi
}

verify_db() {
  local db_path="$1"
  local label="$2"

  python3 - "$db_path" "$label" <<'PY'
import sys
from pathlib import Path

import duckdb

db_path = Path(sys.argv[1])
label = sys.argv[2]

if not db_path.exists() or db_path.stat().st_size == 0:
    print(f"[verify] ERROR: {label} DB missing/empty: {db_path}")
    raise SystemExit(1)

conn = duckdb.connect(str(db_path), read_only=True)
rows = conn.execute("SELECT COUNT(*) FROM signal_observations").fetchone()[0]
conn.close()
print(f"[verify] {label} DB readable: {db_path} rows={rows:,}")
PY
}

main() {
  mkdir -p "$OUT_DIR" "$TMP_DIR"
  : > "$LOG"

  {
    log "Starting safe Industroyer 1hr DB rerun"
    log "Existing augmented graph kept at: $EXISTING_AUG"
    log "Rerun augmented graph will be written to: $RERUN_AUG"
    log "TMPDIR: $TMP_DIR"

    if [[ ! -s "$BASE_CYPHER" ]]; then
      log "ERROR: missing base graph: $BASE_CYPHER"
      exit 1
    fi

    if [[ ! -d "$PCAP_DIR" ]]; then
      log "ERROR: missing PCAP directory: $PCAP_DIR"
      exit 1
    fi

    backup_if_exists "$RERUN_AUG"
    backup_if_exists "$MAIN_DB"
    backup_if_exists "$MAIN_DB.wal"
    backup_if_exists "$MQTT_DB"
    backup_if_exists "$MQTT_DB.wal"
    backup_if_exists "$OPCUA_DB"
    backup_if_exists "$OPCUA_DB.wal"
    backup_if_exists "$CACHE"

    log "Running streaming augmentation with signal DB"
    TMPDIR="$TMP_DIR" python3 -m network_aug \
      --base-cypher "$BASE_CYPHER" \
      --output-cypher "$RERUN_AUG" \
      --pcap-dir "$PCAP_DIR" \
      --assets "$ASSETS" \
      --cache "$CACHE" \
      --force-rebuild \
      --streaming \
      --signal-db "$MAIN_DB"

    log "Running standalone MQTT/OPC UA extraction"
    TMPDIR="$TMP_DIR" python3 -m invariantExperiments.extract_protocol_signals \
      "$PCAP_DIR" \
      --mqtt-db "$MQTT_DB" \
      --opcua-db "$OPCUA_DB" \
      --assets "$ASSETS" \
      --force-rebuild

    log "Verifying DBs"
    verify_db "$MAIN_DB" "main Modbus"
    verify_db "$MQTT_DB" "MQTT"
    verify_db "$OPCUA_DB" "OPC UA"

    if [[ -s "$RERUN_AUG" ]]; then
      log "Rerun augmented graph exists: $RERUN_AUG"
    else
      log "ERROR: rerun augmented graph missing/empty: $RERUN_AUG"
      exit 1
    fi

    log "Safe Industroyer rerun complete"
  } >> "$LOG" 2>&1
}

main "$@"
