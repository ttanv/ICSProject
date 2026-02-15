"""Helpers for turning augmented data into Cypher statements."""

from __future__ import annotations

from typing import Dict


def escape_cypher_string(value: str) -> str:
    """Escape characters that would break Cypher string literals."""
    return value.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')


def format_properties(properties: Dict[str, object]) -> str:
    """Format a dictionary into a Cypher property map."""
    parts = []
    for key, value in properties.items():
        if value is None:
            continue
        if isinstance(value, bool):
            parts.append(f"{key}: {'true' if value else 'false'}")
        elif isinstance(value, (int, float)):
            parts.append(f"{key}: {value}")
        else:
            parts.append(f"{key}: '{escape_cypher_string(str(value))}'")
    return "{%s}" % ", ".join(parts)


def create_asset_statement(asset_guid: str, properties: Dict[str, object]) -> str:
    """Return a MERGE statement for an Asset node keyed by guid."""
    property_map = format_properties(properties)
    guid = escape_cypher_string(asset_guid)
    return (
        f"MERGE (n:Asset {{guid: '{guid}'}})\n"
        f"ON CREATE SET n += {property_map}\n"
        f"SET n.pcapAugmented = true;"
    )


def create_host_statement(host_guid: str, properties: Dict[str, object]) -> str:
    """Return a MERGE statement for a Host node (external/unknown host) keyed by guid.

    Host nodes represent external or unknown destinations that are not part of
    the known asset inventory. These are used as targets for ESTABLISH_EXTERNAL_CONNECTION
    relationships.
    """
    property_map = format_properties(properties)
    guid = escape_cypher_string(host_guid)
    return (
        f"MERGE (n:Host {{guid: '{guid}'}})\n"
        f"ON CREATE SET n += {property_map}\n"
        f"SET n.pcapAugmented = true;"
    )


def create_network_service_statement(
    service_guid: str,
    properties: Dict[str, object],
    asset_guid: str,
) -> str:
    """Return a MERGE statement for a NetworkService node plus SERVED_ON edge."""
    property_map = format_properties(properties)
    svc_guid = escape_cypher_string(service_guid)
    asset = escape_cypher_string(asset_guid)
    return (
        f"MATCH (m:Asset {{guid: '{asset}'}})\n"
        f"MERGE (n:NetworkService {{guid: '{svc_guid}'}})\n"
        f"ON CREATE SET n += {property_map}\n"
        f"SET n.pcapAugmented = true\n"
        f"MERGE (n)-[:SERVED_ON]->(m);"
    )


def create_register_statement(
    register_guid: str,
    properties: Dict[str, object],
    asset_guid: str,
) -> str:
    """Return a MERGE statement for a Register node and related edges."""
    property_map = format_properties(properties)
    reg_guid = escape_cypher_string(register_guid)
    asset = escape_cypher_string(asset_guid)
    return (
        f"MATCH (m1:Asset {{guid: '{asset}'}})\n"
        f"MERGE (n:Register {{guid: '{reg_guid}'}})\n"
        f"ON CREATE SET n += {property_map}\n"
        f"SET n += {property_map}\n"
        f"SET n.pcapAugmented = true\n"
        f"MERGE (m1)-[:HAS_REGISTER]->(n);"
    )


def create_virtual_process_statement(
    process_guid: str,
    properties: Dict[str, object],
) -> str:
    """Return a MERGE statement for a Virtual Process node (placeholder for PLCs/RTUs)."""
    property_map = format_properties(properties)
    guid = escape_cypher_string(process_guid)
    return (
        f"MERGE (n:Process {{guid: '{guid}'}})\n"
        f"ON CREATE SET n += {property_map}\n"
        f"SET n.pcapAugmented = true;"
    )


def create_runs_relationship_statement(
    asset_guid: str,
    process_guid: str,
) -> str:
    """Return a MERGE statement for Asset-[:RUNS]->Process relationship."""
    asset = escape_cypher_string(asset_guid)
    proc = escape_cypher_string(process_guid)
    return (
        f"MATCH (a:Asset {{guid: '{asset}'}})\n"
        f"MATCH (p:Process {{guid: '{proc}'}})\n"
        f"MERGE (a)-[:RUNS]->(p);"
    )


def create_connection_statement(
    source_guid: str,
    dest_guid: str,
    properties: Dict[str, object],
    relationship_name: str = "ESTABLISH_CONNECTION",
    source_label: str = "NetworkService",
    dest_label: str = "NetworkService",
) -> str:
    property_map = format_properties(properties)
    src = escape_cypher_string(source_guid)
    dst = escape_cypher_string(dest_guid)
    return (
        f"MATCH (m1:{source_label} {{guid: '{src}'}}), (m2:{dest_label} {{guid: '{dst}'}})\n"
        f"MERGE (m1)-[r:{relationship_name}]->(m2)\n"
        f"SET r += {property_map}\n"
        f"SET r.pcapAugmented = true;"
    )


def create_signal_container_statement(
    signal_guid: str,
    properties: Dict[str, object],
    service_guid: str,
) -> str:
    """Return a MERGE statement for a SignalContainer node with OBSERVED relationship.

    The new graph structure is:
        NetworkService -[OBSERVED]-> SignalContainer

    This replaces the old Register node structure which had redundant Asset links.

    Args:
        signal_guid: Deterministic GUID for the SignalContainer node.
        properties: Node properties including address, segments, stats.
        service_guid: GUID of the NetworkService that observed this signal.

    Returns:
        Cypher MERGE statement creating the node and relationship.
    """
    property_map = format_properties(properties)
    sig_guid = escape_cypher_string(signal_guid)
    svc = escape_cypher_string(service_guid)
    return (
        f"MATCH (svc:NetworkService {{guid: '{svc}'}})\n"
        f"MERGE (sig:SignalContainer {{guid: '{sig_guid}'}})\n"
        f"ON CREATE SET sig += {property_map}\n"
        f"SET sig += {property_map}\n"
        f"SET sig.pcapAugmented = true\n"
        f"MERGE (svc)-[:OBSERVED]->(sig);"
    )


def create_accessed_signal_statement(
    process_guid: str,
    signal_guid: str,
    properties: Dict[str, object],
) -> str:
    """Return a MERGE statement for Process -[ACCESSED_SIGNAL]-> SignalContainer.

    This relationship indicates that a process accessed (read/wrote) a signal,
    determined through temporal correlation of PCAP traffic to telemetry.

    Args:
        process_guid: GUID of the Process node.
        signal_guid: GUID of the SignalContainer node.
        properties: Relationship properties (accessType, readCount, writeCount, etc.).

    Returns:
        Cypher MERGE statement creating the relationship.
    """
    property_map = format_properties(properties)
    proc = escape_cypher_string(process_guid)
    sig = escape_cypher_string(signal_guid)
    return (
        f"MATCH (proc:Process {{guid: '{proc}'}})\n"
        f"MATCH (sig:SignalContainer {{guid: '{sig}'}})\n"
        f"MERGE (proc)-[acc:ACCESSED_SIGNAL]->(sig)\n"
        f"SET acc += {property_map}\n"
        f"SET acc.pcapAugmented = true;"
    )
