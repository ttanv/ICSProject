#!/usr/bin/env bash
set -euo pipefail

# === CONFIGURATION ===
NEO4J_SERVICE="neo4j"
NEO4J_USER="neo4j"
NEO4J_PASS="icsproject"
DB_NAME="neo4j"
DATA_DIR="/var/lib/neo4j/data"

# === FUNCTIONS ===
log() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

err() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
    exit 1
}

# === ARGUMENT CHECK ===
if [[ $# -lt 1 ]]; then
    err "Usage: $0 <export_file.cypher>"
fi

EXPORT_FILE="$1"

# === MAIN SCRIPT ===
log "Stopping Neo4j service..."
sudo systemctl stop "$NEO4J_SERVICE" || err "Failed to stop Neo4j"

log "Removing transaction and database data..."
for path in \
    "$DATA_DIR/transactions/$DB_NAME" \
    "$DATA_DIR/databases/$DB_NAME"
do
    if [[ -d "$path" ]]; then
        sudo rm -rf "$path"
        log "Deleted $path"
    else
        log "Path $path does not exist, skipping."
    fi
done

log "Starting Neo4j service..."
sudo systemctl start "$NEO4J_SERVICE" || err "Failed to start Neo4j"

log "Waiting for Neo4j to become available..."
sleep 10

log "Importing Cypher file: $EXPORT_FILE"
if [[ -f "$EXPORT_FILE" ]]; then
    cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASS" < "$EXPORT_FILE" || err "Cypher import failed"
    log "Import completed successfully."
else
    err "Export file not found: $EXPORT_FILE"
fi
