#!/usr/bin/env bash
set -euo pipefail

# === CONFIGURATION ===
NEO4J_CONTAINER="neo4j"
NEO4J_USER="neo4j"
NEO4J_PASS="CPS@QCRI2255"       # update as needed
DB_NAME="neo4j"

# === FUNCTIONS ===
log() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

err() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
    exit 1
}

wait_for_neo4j() {
    log "Waiting for Neo4j to accept Bolt connections..."
    for i in {1..30}; do
        if docker exec "$NEO4J_CONTAINER" \
            cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASS" "RETURN 1;" \
            &>/dev/null; then
            log "Neo4j is ready."
            return
        fi
        sleep 2
    done
    err "Neo4j did not become ready in time."
}

# === ARGUMENT CHECK ===
if [[ $# -lt 1 ]]; then
    err "Usage: $0 <export_file.cypher>"
fi

EXPORT_FILE="$1"
[[ ! -f "$EXPORT_FILE" ]] && err "Export file not found: $EXPORT_FILE"

# === MAIN SCRIPT ===

# Ensure container exists
if ! docker ps -a --format '{{.Names}}' | grep -q "^$NEO4J_CONTAINER$"; then
    err "Docker container '$NEO4J_CONTAINER' does not exist."
fi

log "Stopping Neo4j container..."
docker stop "$NEO4J_CONTAINER" >/dev/null

log "Starting Neo4j container in maintenance mode..."
docker start "$NEO4J_CONTAINER" >/dev/null

wait_for_neo4j

log "Deleting existing Neo4j database from inside the container..."
docker exec "$NEO4J_CONTAINER" bash -c "
    rm -rf /data/databases/$DB_NAME/* &&
    rm -rf /data/transactions/$DB_NAME/*
" || err "Failed to delete existing database data."

log "Database cleared."

log "Importing Cypher file: $EXPORT_FILE"
docker exec -i "$NEO4J_CONTAINER" cypher-shell \
    -u "$NEO4J_USER" -p "$NEO4J_PASS" < "$EXPORT_FILE" \
    || err "Cypher import failed."

log "Import completed successfully."
