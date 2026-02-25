"""Utilities for reading the Neo4j export produced by the base notebook."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from .models import ConnectionKey

logger = logging.getLogger(__name__)

_NODE_MERGE_REGEX = re.compile(r"MERGE\s*\((?P<alias>\w+):(?P<label>\w+)\s*\{", re.IGNORECASE)
_MATCH_NODE_REGEX = re.compile(r"\((?P<alias>\w+):(?P<label>\w+)\s*\{", re.IGNORECASE)
# Match both MERGE and CREATE relationship patterns
_REL_ALIAS_REGEX = re.compile(r"(?:MERGE|CREATE)\s*\((?P<src>\w+)\)\s*-\[.*?\]->\s*\((?P<dst>\w+)\)", re.IGNORECASE | re.DOTALL)


def _looks_like_ip(value: str) -> bool:
    """Return True if the string resembles an IPv4 address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


@dataclass(frozen=True)
class ExistingConnection:
    """Context needed to enrich an existing relationship."""

    key: ConnectionKey
    rel_type: str
    src_guid: str
    src_label: str
    dst_guid: str
    dst_label: str
    properties: Dict[str, object]


class CypherConnectionExtractor:
    """Parse Cypher files and extract existing network connection properties."""

    def __init__(
        self,
        cypher_path: Path,
        relationship_types: Sequence[str] | None = None,
        asset_file: Optional[Path] = None,
    ) -> None:
        self.cypher_path = Path(cypher_path)
        # For graphs with separate internal/external types, use:
        # default_types = ("ESTABLISH_INTERNAL_CONNECTION", "ESTABLISH_EXTERNAL_CONNECTION")
        default_types = ("ESTABLISH_CONNECTION",)
        self.relationship_types = tuple(rel.upper() for rel in (relationship_types or default_types))
        pattern = "|".join(re.escape(rel) for rel in self.relationship_types)
        # Pattern handles both [alias:TYPE and [:TYPE (no alias) formats
        self._rel_regex = re.compile(rf"\[\s*\w*\s*:\s*(?P<type>{pattern})", re.IGNORECASE)
        self._asset_file = Path(asset_file) if asset_file else None
        self._node_cache: Dict[str, Dict[str, object]] = {}
        self._host_ip_map: Dict[str, str] = {}  # hostname -> primary IP
        self._ip_host_map: Dict[str, str] = {}  # ALL IPs -> hostname (for normalization)
        self._caches_built = False

    def load_connections(self) -> List[ExistingConnection]:
        """Return all connection statements found in the Cypher export with context."""
        if not self.cypher_path.exists():
            raise FileNotFoundError(f"Cypher file not found: {self.cypher_path}")

        text = self.cypher_path.read_text(encoding="utf-8")
        statements = _split_statements(text)
        self._ensure_caches(statements)

        connections: List[ExistingConnection] = []

        for stmt in statements:
            alias_map = self._extract_match_aliases(stmt)
            if not alias_map:
                continue

            src_alias, dst_alias = self._extract_merge_aliases(stmt)
            if not src_alias or not dst_alias:
                continue

            src_info = alias_map.get(src_alias, {})
            dst_info = alias_map.get(dst_alias, {})
            src_guid = src_info.get("guid", "")
            dst_guid = dst_info.get("guid", "")

            for match in self._rel_regex.finditer(stmt):
                rel_type = match.group("type").upper()
                props = self._extract_properties(stmt, match.end())
                if not props:
                    continue

                normalized_props = self._augment_connection_props(props, src_guid, dst_guid)
                try:
                    key = ConnectionKey.from_dict(normalized_props)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("Failed to build ConnectionKey: %s", exc)
                    continue

                if not key.src_ip or not key.dst_ip:
                    logger.debug(
                        "Dropping connection %s->%s: missing IP (src_ip=%r, dst_ip=%r)",
                        src_guid, dst_guid, key.src_ip, key.dst_ip,
                    )
                    continue
                if key.dst_port <= 0:
                    logger.debug(
                        "Dropping connection %s->%s (dst_ip=%s): dst_port=%d <= 0",
                        src_guid, dst_guid, key.dst_ip, key.dst_port,
                    )
                    continue

                connections.append(
                    ExistingConnection(
                        key=key,
                        rel_type=rel_type,
                        src_guid=str(src_guid or ""),
                        src_label=str(src_info.get("label") or ""),
                        dst_guid=str(dst_guid or ""),
                        dst_label=str(dst_info.get("label") or ""),
                        properties=dict(normalized_props),
                    )
                )

        logger.info(
            "Extracted %d connection statements from %s",
            len(connections),
            self.cypher_path,
        )
        return connections

    @property
    def ip_to_hostname_map(self) -> Dict[str, str]:
        """Return mapping of ALL IPs to hostnames for normalization."""
        if not self._caches_built:
            self._ensure_caches([])
        return self._ip_host_map

    def _ensure_caches(self, statements: Sequence[str]) -> None:
        if self._caches_built:
            return
        self._build_node_cache(statements)
        self._load_asset_hosts()
        self._caches_built = True

    def _build_node_cache(self, statements: Sequence[str]) -> None:
        for stmt in statements:
            match = _NODE_MERGE_REGEX.search(stmt)
            if not match:
                continue

            brace_start = match.end() - 1
            if brace_start < 0 or stmt[brace_start] != "{":
                brace_start = stmt.find("{", match.end())
            if brace_start == -1:
                continue

            block, _ = _consume_brace_block(stmt, brace_start)
            if not block:
                continue

            properties = _parse_property_block(block)
            guid = str(properties.get("guid") or "").strip()
            if not guid:
                continue

            label = match.group("label")
            cached = {"label": label, "props": properties}
            self._node_cache.setdefault(guid, cached)

            label_lower = label.lower()
            if label_lower == "asset":
                hostname = str(properties.get("hostname") or "").strip()
                # Handle both ipAddress (singular) and ipAddresses (plural/array) formats
                ip_addresses = properties.get("ipAddresses") or properties.get("ip_addresses")
                if isinstance(ip_addresses, list) and ip_addresses:
                    for i, ip in enumerate(ip_addresses):
                        ip_str = str(ip or "").strip()
                        if hostname and ip_str:
                            if i == 0:
                                self._host_ip_map.setdefault(hostname, ip_str)
                            self._ip_host_map[ip_str] = hostname
                else:
                    ip_address = str(properties.get("ipAddress") or "").strip()
                    if hostname and ip_address:
                        self._host_ip_map.setdefault(hostname, ip_address)
                        self._ip_host_map[ip_address] = hostname
            elif label_lower == "networkservice":
                hostname = str(properties.get("host") or "").strip()
                ip_address = str(properties.get("ipAddress") or "").strip()
                if hostname and ip_address:
                    self._host_ip_map.setdefault(hostname, ip_address)
                    self._ip_host_map[ip_address] = hostname

    def _load_asset_hosts(self) -> None:
        if not self._asset_file:
            candidate = self.cypher_path.parent / "assets.yaml"
            if candidate.exists():
                self._asset_file = candidate

        if not self._asset_file or not self._asset_file.exists():
            return

        try:
            with self._asset_file.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Failed to load asset inventory from %s: %s", self._asset_file, exc)
            return

        hosts = data.get("hosts", {}) if isinstance(data, dict) else {}
        for hostname, details in hosts.items():
            if not isinstance(details, dict):
                continue
            # Handle ip_addresses list format
            ip_addresses = details.get("ip_addresses")
            if isinstance(ip_addresses, list) and ip_addresses:
                for i, ip in enumerate(ip_addresses):
                    ip_str = str(ip or "").strip()
                    if hostname and ip_str:
                        # First IP is primary for hostname -> IP lookup
                        if i == 0:
                            self._host_ip_map.setdefault(hostname, ip_str)
                        # ALL IPs map back to hostname for normalization
                        self._ip_host_map[ip_str] = hostname
            else:
                # Fallback to single ip_address format
                ip_address = details.get("ip_address") or details.get("ipAddress") or details.get("ip")
                ip_address = str(ip_address or "").strip()
                if hostname and ip_address:
                    self._host_ip_map.setdefault(hostname, ip_address)
                    self._ip_host_map[ip_address] = hostname

    def _extract_match_aliases(self, statement: str) -> Dict[str, Dict[str, str]]:
        # Find where the relationship clause starts (MERGE or CREATE)
        merge_index = statement.find("MERGE")
        create_index = statement.find("CREATE")
        # Use the first occurrence of either MERGE or CREATE
        if merge_index == -1 and create_index == -1:
            return {}
        elif merge_index == -1:
            rel_index = create_index
        elif create_index == -1:
            rel_index = merge_index
        else:
            rel_index = min(merge_index, create_index)

        alias_info: Dict[str, Dict[str, str]] = {}
        match_section = statement[:rel_index]

        for node_match in _MATCH_NODE_REGEX.finditer(match_section):
            alias = node_match.group("alias")
            brace_start = node_match.end() - 1
            if brace_start < 0 or match_section[brace_start] != "{":
                brace_start = match_section.find("{", node_match.end())
            if brace_start == -1:
                continue
            block, _ = _consume_brace_block(match_section, brace_start)
            if not block:
                continue

            properties = _parse_property_block(block)
            guid = str(properties.get("guid") or "").strip()
            if not guid:
                continue

            alias_info[alias] = {"label": node_match.group("label"), "guid": guid}

        return alias_info

    def _extract_merge_aliases(self, statement: str) -> Tuple[str, str]:
        match = _REL_ALIAS_REGEX.search(statement)
        if not match:
            return "", ""
        return match.group("src"), match.group("dst")

    def _extract_properties(self, stmt: str, start_index: int) -> Optional[Dict[str, object]]:
        """Extract the property dictionary that follows a relationship pattern."""
        brace_start = stmt.find("{", start_index)
        if brace_start == -1:
            return None

        block, brace_end = _consume_brace_block(stmt, brace_start)
        if brace_end == -1:
            return None

        properties = _parse_property_block(block)
        return properties

    def _augment_connection_props(
        self,
        props: Dict[str, object],
        src_guid: Optional[str],
        dst_guid: Optional[str],
    ) -> Dict[str, object]:
        augmented = dict(props)
        src_node = self._node_cache.get(src_guid or "")
        dst_node = self._node_cache.get(dst_guid or "")

        src_ip = self._first_value(augmented, ("SourceIp", "sourceIp", "sourceIP"))
        if not src_ip:
            src_ip = self._ip_from_node(src_node)
        if src_ip:
            augmented["SourceIp"] = src_ip

        dst_ip = self._first_value(
            augmented,
            ("DestinationIp", "destinationIp", "destinationIP", "DestIp", "destIp"),
        )
        if not dst_ip:
            dst_ip = self._ip_from_node(dst_node)
        if dst_ip:
            augmented["DestinationIp"] = dst_ip

        src_port_value = self._first_value(augmented, ("SourcePort", "sourcePort"))
        if src_port_value in ("", None):
            src_port_value = None
        if src_port_value is None and src_node:
            src_port_value = self._port_from_node(src_node)
        augmented["SourcePort"] = self._coerce_port(src_port_value)

        dst_port_value = self._first_value(
            augmented,
            ("DestinationPort", "destinationPort", "DestPort", "destPort"),
        )
        if dst_port_value in ("", None):
            dst_port_value = None
        if dst_port_value is None and dst_node:
            dst_port_value = self._port_from_node(dst_node)
        augmented["DestinationPort"] = self._coerce_port(dst_port_value)

        protocol = self._first_value(augmented, ("Protocol", "protocol"))
        if not protocol:
            protocol = self._protocol_from_nodes(src_node, dst_node)
        augmented["Protocol"] = (protocol or "tcp")

        # Copy process properties from source node if it's a Process
        if src_node and src_node.get("label", "").lower() == "process":
            src_props = src_node.get("props", {})
            if "Image" not in augmented and "image" not in augmented:
                image = src_props.get("image") or src_props.get("Image") or ""
                if image:
                    augmented["Image"] = image
            if "ProcessId" not in augmented and "processId" not in augmented:
                pid = src_props.get("processId") or src_props.get("ProcessId") or ""
                if pid:
                    augmented["ProcessId"] = pid
            if "User" not in augmented and "user" not in augmented:
                user = src_props.get("user") or src_props.get("User") or ""
                if user:
                    augmented["User"] = user

        return augmented

    @staticmethod
    def _first_value(properties: Dict[str, object], keys: Sequence[str]) -> str:
        for key in keys:
            value = properties.get(key)
            if value in (None, "", "None"):
                continue
            return str(value).strip()
        return ""

    def _ip_from_node(self, node: Optional[Dict[str, object]]) -> str:
        if not node:
            return ""
        props = node.get("props", {})
        ip_address = str(
            props.get("ipAddress")
            or props.get("ip")
            or props.get("address")
            or ""
        ).strip()
        if ip_address:
            return ip_address

        hostname = str(props.get("host") or props.get("hostname") or "").strip()
        if not hostname:
            return ""

        if _looks_like_ip(hostname):
            return hostname

        return self._host_ip_map.get(hostname, "")

    @staticmethod
    def _port_from_node(node: Dict[str, object]) -> int:
        props = node.get("props", {})
        for key in ("port", "destinationPort", "localPort"):
            if key not in props:
                continue
            value = props[key]
            coerced = CypherConnectionExtractor._coerce_port(value)
            if coerced > 0:
                return coerced
        return 0

    @staticmethod
    def _protocol_from_nodes(
        src_node: Optional[Dict[str, object]],
        dst_node: Optional[Dict[str, object]],
    ) -> str:
        for node in (dst_node, src_node):
            if not node:
                continue
            props = node.get("props", {})
            protocol = props.get("protocol") or props.get("Protocol")
            if protocol:
                return str(protocol).strip()
        return "tcp"

    @staticmethod
    def _coerce_port(value: object) -> int:
        if value in (None, "", "None"):
            return 0
        if isinstance(value, str):
            cleaned = value.strip()
            if not cleaned or cleaned.lower() in {"aggregated", "any", "unknown"}:
                return 0
            value = cleaned
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            try:
                return int(float(value))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return 0


def _split_statements(text: str) -> List[str]:
    """Split Cypher text into statements while respecting braces and quotes."""
    statements: List[str] = []
    current: List[str] = []
    depth = 0
    in_quote: Optional[str] = None
    escape = False

    for char in text:
        current.append(char)

        if escape:
            escape = False
            continue

        if char == "\\":
            escape = True
            continue

        if in_quote:
            if char == in_quote:
                in_quote = None
            continue

        if char in ("'", '"'):
            in_quote = char
            continue

        if char in "{[(":
            depth += 1
        elif char in "}])":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []

    remainder = "".join(current).strip()
    if remainder:
        statements.append(remainder)
    return statements


def _consume_brace_block(text: str, start: int) -> Tuple[str, int]:
    """Return the substring for a balanced brace block and the index of its end."""
    if start >= len(text) or text[start] != "{":
        raise ValueError("Brace block must start with '{'")

    depth = 0
    in_quote: Optional[str] = None
    escape = False
    for idx in range(start, len(text)):
        char = text[idx]

        if escape:
            escape = False
            continue

        if char == "\\":
            escape = True
            continue

        if in_quote:
            if char == in_quote:
                in_quote = None
            continue

        if char in ("'", '"'):
            in_quote = char
            continue

        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                block = text[start + 1 : idx]
                return block, idx

    return "", -1


def _parse_property_block(block: str) -> Dict[str, object]:
    """Parse a comma-separated property string into a dictionary."""
    properties: Dict[str, object] = {}
    for token in _split_by_comma(block):
        if ":" not in token:
            continue
        key, value = token.split(":", 1)
        key = key.strip()
        parsed_value = _parse_value(value.strip())
        properties[key] = parsed_value
    return properties


def _split_by_comma(block: str) -> Iterable[str]:
    """Split a string by commas while respecting quotes, nested braces, and brackets."""
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    in_quote: Optional[str] = None
    escape = False

    for char in block:
        if escape:
            current.append(char)
            escape = False
            continue

        if char == "\\":
            current.append(char)
            escape = True
            continue

        if in_quote:
            current.append(char)
            if char == in_quote:
                in_quote = None
            continue

        if char in ("'", '"'):
            current.append(char)
            in_quote = char
            continue

        if char in "{[":
            depth += 1
            current.append(char)
            continue
        if char in "}]":
            depth = max(0, depth - 1)
            current.append(char)
            continue

        if char == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue

        current.append(char)

    remainder = "".join(current).strip()
    if remainder:
        parts.append(remainder)
    return parts


def _parse_value(value: str) -> object:
    """Parse a Cypher literal into a Python object."""
    if not value:
        return ""
    # Handle arrays: [value1, value2, ...]
    if value.startswith("[") and value.endswith("]"):
        return _parse_array(value[1:-1])
    if value[0] in ("'", '"') and value[-1] == value[0]:
        return value[1:-1]
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "null":
        return None
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _parse_array(content: str) -> List[object]:
    """Parse the content of a Cypher array literal into a Python list."""
    if not content.strip():
        return []

    result: List[object] = []
    for item in _split_by_comma(content):
        item = item.strip()
        if not item:
            continue
        result.append(_parse_value(item))
    return result
