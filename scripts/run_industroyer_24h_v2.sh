#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

SLUG="Industroyer"
LOG_DIR="logs/extracted/Industroyer"
PCAP_DIR="pcap_traffic/extracted/Industroyer"
OUT_DIR="paper_graphs_v2/id_24h"
ASSETS="ICSGraph/Collection/assets.yaml"
TMP_DIR="$OUT_DIR/tmp"
RUN_LOG="$OUT_DIR/Industroyer_24h_extract.log"

BASE_CYPHER="$OUT_DIR/base_Industroyer.cypher"
AUG_CYPHER="$OUT_DIR/augmented_Industroyer.cypher"
MAIN_DB="$OUT_DIR/Industroyer_signals.duckdb"
MQTT_DB="$OUT_DIR/Industroyer_mqtt_signals.duckdb"
OPCUA_DB="$OUT_DIR/Industroyer_opcua_signals.duckdb"
INVARIANTS_JSON="$OUT_DIR/Industroyer_invariants.json"
CACHE="$OUT_DIR/Industroyer_pcap_index.pkl"
PROTOCOL_CACHE="$OUT_DIR/Industroyer_protocol_signal_extract_cache.pkl"

log() {
  printf '[%s] %s\n' "$(date -Is)" "$*"
}

backup_if_exists() {
  local path="$1"
  if [[ -e "$path" ]]; then
    mv "$path" "${path}.partial_$(date +%Y%m%d_%H%M%S)"
  fi
}

pcap_count() {
  find "$PCAP_DIR" -maxdepth 1 -type f \( -name '*.pcap' -o -name '*.pcapng' \) | wc -l
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
  : > "$RUN_LOG"

  {
    log "Starting Industroyer 24h extraction into $OUT_DIR"
    log "Logs: $LOG_DIR"
    log "PCAPs: $PCAP_DIR"
    log "TMPDIR: $TMP_DIR"

    if [[ ! -d "$LOG_DIR" ]]; then
      log "ERROR: missing log directory: $LOG_DIR"
      exit 1
    fi

    if [[ ! -d "$PCAP_DIR" ]]; then
      log "ERROR: missing PCAP directory: $PCAP_DIR"
      exit 1
    fi

    local count
    count="$(pcap_count)"
    log "PCAP count: $count"
    if [[ "$count" -eq 0 ]]; then
      log "ERROR: no PCAP/PCAPNG files found"
      exit 1
    fi

    backup_if_exists "$BASE_CYPHER"
    backup_if_exists "$AUG_CYPHER"
    backup_if_exists "$MAIN_DB"
    backup_if_exists "$MAIN_DB.wal"
    backup_if_exists "$MQTT_DB"
    backup_if_exists "$MQTT_DB.wal"
    backup_if_exists "$OPCUA_DB"
    backup_if_exists "$OPCUA_DB.wal"
    backup_if_exists "$INVARIANTS_JSON"
    backup_if_exists "$CACHE"
    backup_if_exists "$PROTOCOL_CACHE"

    log "[1/4] Building base graph"
    TMPDIR="$TMP_DIR" python3 ICSGraph/Collection/build_graph.py \
      --logs "$LOG_DIR" \
      --assets "$ASSETS" \
      --output "$BASE_CYPHER" \
      --workers 8

    if [[ ! -s "$BASE_CYPHER" ]]; then
      log "ERROR: base graph missing/empty: $BASE_CYPHER"
      exit 1
    fi

    log "[2/4] Running streaming augmentation with main Modbus DuckDB"
    TMPDIR="$TMP_DIR" python3 -m network_aug \
      --base-cypher "$BASE_CYPHER" \
      --output-cypher "$AUG_CYPHER" \
      --pcap-dir "$PCAP_DIR" \
      --assets "$ASSETS" \
      --cache "$CACHE" \
      --force-rebuild \
      --streaming \
      --signal-db "$MAIN_DB"

    log "[3/4] Running standalone MQTT/OPC UA extraction"
    TMPDIR="$TMP_DIR" python3 -m invariantExperiments.extract_protocol_signals \
      "$PCAP_DIR" \
      --mqtt-db "$MQTT_DB" \
      --opcua-db "$OPCUA_DB" \
      --assets "$ASSETS" \
      --cache "$PROTOCOL_CACHE" \
      --force-rebuild

    log "[4/4] Mining invariants from Modbus signal DB"
    TMPDIR="$TMP_DIR" python3 -m network_aug.invariants \
      --signal-db "$MAIN_DB" \
      --output "$INVARIANTS_JSON"

    log "Verifying outputs"
    if [[ ! -s "$BASE_CYPHER" ]]; then
      log "ERROR: missing/empty base graph: $BASE_CYPHER"
      exit 1
    fi
    if [[ ! -s "$AUG_CYPHER" ]]; then
      log "ERROR: missing/empty augmented graph: $AUG_CYPHER"
      exit 1
    fi
    if [[ ! -s "$INVARIANTS_JSON" ]]; then
      log "ERROR: missing/empty invariants: $INVARIANTS_JSON"
      exit 1
    fi

    verify_db "$MAIN_DB" "main Modbus"
    verify_db "$MQTT_DB" "MQTT"
    verify_db "$OPCUA_DB" "OPC UA"

    log "Industroyer 24h extraction complete"
  } >> "$RUN_LOG" 2>&1
}

main "$@"
