#!/usr/bin/env python3
"""
ICS Provenance Graph Builder

Processes Industrial Control System (ICS) forensics data from Velociraptor logs
into a provenance graph with Neo4j Cypher export.

Data Sources:
    - Sysmon: Process, network, registry, and file events
    - FileIO: File access operations
    - PsList: Running process baseline
    - ListeningTable: Network service baseline
    - Services: Windows services inventory
    - Tasks: Scheduled tasks inventory

Usage:
    python build_graph.py [--logs LOGS_DIR] [--assets ASSETS_FILE] [--output OUTPUT_FILE]
    python build_graph.py --logs ./logs --assets ./assets.yaml --output ./neo4j_export.cypher

Example:
    python build_graph.py
    python build_graph.py --logs ./logs --no-cache --verbose
"""

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import pickle
import re
import sys
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd
import yaml

# =============================================================================
# SCHEMA DEFINITIONS
# =============================================================================

EVENT_RELATIONSHIPS = {
    # Process Events (1-10)
    1: "CREATE_PROCESS",
    2: "TERMINATE_PROCESS",
    3: "ACCESS_PROCESS",
    4: "INJECT_THREAD",
    5: "TAMPER_PROCESS",
    # File Events (11-20)
    11: "CREATE_FILE",
    12: "DELETE_FILE_ARCHIVED",
    13: "DELETE_FILE",
    14: "CHANGE_FILE_CREATION_TIME",
    15: "CREATE_FILE_STREAM",
    16: "READ_FILE",
    17: "WRITE_FILE",
    # Image/Driver Load Events (21-25)
    21: "LOAD_IMAGE",
    # Network Events (31-40)
    31: "BINDS",
    32: "QUERY_DNS",
    33: "CONNECT_TO",
    # Registry Events (41-50)
    41: "CREATE_REGISTRY_KEY",
    42: "SET_REGISTRY_VALUE",
    43: "RENAME_REGISTRY_KEY",
    # Named Pipe Events (51-55)
    51: "CREATE_PIPE",
    52: "CONNECT_PIPE",
    # WMI Events (61-65)
    61: "WMI_FILTER",
    62: "WMI_CONSUME",
    63: "WMI_LINK_CONSUMER",
    # Raw Access Events (71-75)
    71: "RAW_DISK_READ",
    # Service Events (81-85)
    82: "START_SERVICE",
    83: "STOP_SERVICE",
    84: "MODIFY_SERVICE",
    # Scheduled Task Events (91-95)
    91: "SCHEDULED_BY",
    92: "EXECUTE_TASK",
    93: "REGISTER_TASK",
    94: "DELETE_TASK",
    95: "DISABLE_TASK",
}

SYSMON_EVENT_MAP = {
    1: 1, 2: 14, 3: 33, 5: 2, 6: 21, 7: 21, 8: 4, 9: 71, 10: 3,
    11: 11, 12: 41, 13: 42, 14: 43, 15: 15, 17: 51, 18: 52,
    19: 61, 20: 62, 21: 63, 22: 32, 23: 12, 25: 5, 26: 13,
}

NODE_TYPES = {
    "NetworkEndpoint": {"pk": "guid", "label": "NetworkEndpoint"},
    "Process": {"pk": "guid", "label": "Process"},
    "File": {"pk": "guid", "label": "File"},
    "NetworkService": {"pk": "guid", "label": "NetworkService"},
    "RegistryKey": {"pk": "guid", "label": "RegistryKey"},
    "DNSName": {"pk": "guid", "label": "DNSName"},
    "Service": {"pk": "guid", "label": "Service"},
    "Task": {"pk": "guid", "label": "Task"},
    "User": {"pk": "guid", "label": "User"},
    "Pipe": {"pk": "guid", "label": "Pipe"},
}

LOG_FILES = {
    "PSLIST": "Process_List.json",
    "SYSMON": "Sysmon_Collector.json",
    "FILEIO": "FileIO.json",
    "LISTENING": "Listeners_List.json",
    "SERVICES": "Services.json",
    "TASKS": "Tasks.json",
}

# Pre-compiled regex for fast timestamp parsing
DATETIME_PATTERN = re.compile(r'Z|\..*')
EPHEMERAL_PORT_THRESHOLD = 32768


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

@lru_cache(maxsize=100000)
def generate_node_guid(node_type: str, hostname: str, *identifiers) -> str:
    """Generate consistent GUID for any node type"""
    components = [node_type, hostname] + [str(i) for i in identifiers if i]
    combined = "|".join(components).lower()
    guid_hash = hashlib.md5(combined.encode()).digest()
    return f"{{{uuid.UUID(bytes=guid_hash)}}}"


def generate_process_guid(hostname: str, pid: str, image: str) -> str:
    """Generate consistent process GUID"""
    if not image:
        image = "<unknown process>"
    process_name = os.path.basename(image).lower().strip()
    return generate_node_guid("Process", hostname, pid, process_name)


def parse_timestamp_fast(ts: str) -> Optional[datetime]:
    """Fast timestamp parsing"""
    if not ts:
        return None
    try:
        clean_ts = DATETIME_PATTERN.sub('', ts)
        return datetime.fromisoformat(clean_ts)
    except:
        return None


# =============================================================================
# ASSET INVENTORY
# =============================================================================

class AssetInventory:
    """Manages asset metadata and network topology"""

    def __init__(self, asset_file: Path, logger: logging.Logger):
        self.assets: Dict[str, dict] = {}
        self.ip_to_host: Dict[str, str] = {}
        self.host_to_ips: Dict[str, List[str]] = {}
        self.logged_hosts: Set[str] = set()
        self.logger = logger
        self._load(asset_file)

    def _load(self, asset_file: Path):
        """Load asset inventory from YAML"""
        self.logger.info(f"Loading asset inventory from {asset_file}")

        with open(asset_file) as f:
            data = yaml.safe_load(f)

        zones = {z: data["zones"][z] for z in data.get("zones", {})}
        hosts = data.get("hosts", {})

        for hostname, asset in hosts.items():
            if "hostname" not in asset:
                asset["hostname"] = hostname

            zone_name = asset.get("zone")
            if zone_name in zones:
                asset["zone_description"] = zones[zone_name].get("description", "")

            self.assets[hostname] = asset

            ips = asset.get("ip_addresses", [])
            if not ips:
                single_ip = asset.get("ip_address")
                if single_ip:
                    ips = [single_ip]
                    asset["ip_addresses"] = ips  # normalize for downstream
            if ips:
                self.host_to_ips[hostname] = ips
                for ip in ips:
                    self.ip_to_host[ip] = hostname

            if asset.get("is_managed", False):
                self.logged_hosts.add(hostname)

        self.logger.info(f"Loaded {len(self.assets)} assets, {len(self.logged_hosts)} with logs")

    def get_asset(self, hostname: str) -> Optional[dict]:
        return self.assets.get(hostname)

    def is_internal(self, ip: str) -> bool:
        return ip in self.ip_to_host

    def should_exclude_external_endpoint_ip(self, ip: str) -> bool:
        """Check if an IP should be excluded from external endpoint creation."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_unspecified
            or addr.is_multicast
        )

    def resolve_ip(self, ip: str) -> str:
        return self.ip_to_host.get(ip, ip)


# =============================================================================
# GRAPH BUILDER
# =============================================================================

class GraphBuilder:
    """Efficient graph construction with batch processing and deduplication"""

    def __init__(self, inventory: AssetInventory):
        self.nodes: Dict[str, dict] = {}
        self.edges: Dict[Tuple[str, str, str], List[dict]] = defaultdict(list)
        self.users: Set[str] = set()
        self.assets: Set[str] = set()
        self.inventory = inventory

    def add_node(self, node_id: str, node_type: str, properties: dict):
        """Add or update node with property merging"""
        if node_id in self.nodes:
            self.nodes[node_id]["props"].update({k: v for k, v in properties.items() if v})
        else:
            self.nodes[node_id] = {
                "type": node_type,
                "props": {k: v for k, v in properties.items() if v}
            }

        if node_type == "User":
            self.users.add(node_id)
        elif properties.get("host"):
            self.assets.add(properties["host"])

    def add_edge(self, from_id: str, to_id: str, rel_type: str, properties: dict):
        """Add edge to graph"""
        edge_key = (from_id, to_id, rel_type)
        self.edges[edge_key].append(properties)

    def add_user(self, username: str, host: str) -> str:
        """Create a User node with host-scoped GUID"""
        if not username:
            return ""
        user_guid = generate_node_guid("User", host, username)
        self.add_node(user_guid, "User", {
            "guid": user_guid,
            "username": username,
            "domain": username.split("\\\\")[0] if "\\\\" in username else "",
            "host": host,
        })
        return user_guid

    def process_event(self, event: dict) -> None:
        """Dispatch event to appropriate handler"""
        event_id = event.get("EventID")
        rel_type = EVENT_RELATIONSHIPS.get(event_id)

        if not rel_type:
            return

        host = event.get("Host") or event.get("Computer", "")

        # Route to specific handlers
        if event_id == 1:
            self._handle_process_create(event, host, rel_type)
        elif event_id in [11, 12, 13, 14, 15, 16, 17, 18, 71]:
            self._handle_file_event(event, host, rel_type)
        elif event_id == 31:
            self._handle_network_service(event, host, rel_type)
        elif event_id == 32:
            self._handle_dns_query(event, host, rel_type)
        elif event_id == 33:
            self._handle_network_connection(event, host, rel_type)
        elif event_id in [41, 42, 43]:
            self._handle_registry_event(event, host, rel_type)
        elif event_id in [51, 52]:
            self._handle_pipe_event(event, host, rel_type)
        elif event_id == 2:
            self._handle_process_terminate(event, host, rel_type)
        elif event_id in [3, 4, 5]:
            self._handle_process_interaction(event, host, rel_type)
        elif event_id == 21:
            self._handle_image_load(event, host, rel_type)
        elif event_id in [82, 83, 84]:
            self._handle_service(event, host, rel_type)
        elif event_id in [91, 92, 93, 94, 95, 96]:
            self._handle_task(event, host, rel_type)

    def _handle_process_create(self, e: dict, host: str, rel: str):
        proc_guid = e.get("ProcessGuid")
        parent_guid = e.get("ParentProcessGuid")
        user = e.get("User", "")

        if not proc_guid:
            return

        if user:
            self.add_user(user, host)

        self.add_node(proc_guid, "Process", {
            "guid": proc_guid,
            "image": e.get("Image", ""),
            "processName": os.path.basename(e.get("Image", "")),
            "processId": e.get("ProcessId", ""),
            "commandLine": e.get("CommandLine", ""),
            "user": user,
            "host": host,
            "createdAt": e.get("UtcTime", ""),
        })

        if parent_guid:
            self.add_node(parent_guid, "Process", {
                "guid": parent_guid,
                "image": e.get("ParentImage", ""),
                "processName": os.path.basename(e.get("ParentImage", "")),
                "host": host,
            })
            self.add_edge(parent_guid, proc_guid, rel, {
                "timestamp": e.get("UtcTime", ""),
                "source": e.get("Source", ""),
            })

    def _handle_file_event(self, e: dict, host: str, rel: str):
        proc_guid = e.get("ProcessGuid")
        file_path = e.get("TargetFilename") or e.get("ImageLoaded") or e.get("Device")

        if not proc_guid or not file_path:
            return

        self.add_node(proc_guid, "Process", {
            "guid": proc_guid,
            "image": e.get("Image", ""),
            "host": host,
        })

        file_guid = generate_node_guid("File", host, file_path.lower())
        self.add_node(file_guid, "File", {
            "guid": file_guid,
            "path": file_path,
            "filename": os.path.basename(file_path),
            "extension": os.path.splitext(file_path)[1].lower(),
            "directory": os.path.dirname(file_path),
            "host": host,
        })

        self.add_edge(proc_guid, file_guid, rel, {
            "timestamp": e.get("UtcTime", ""),
            "source": e.get("Source", ""),
        })

    def _handle_network_service(self, e: dict, host: str, rel: str):
        proc_guid = e.get("ProcessGuid")
        port = e.get("DestinationPort", "")
        image = e.get("Image", "")

        if not port or not proc_guid:
            return

        svc_guid = generate_node_guid("NetworkService", host, port)
        self.add_node(svc_guid, "NetworkService", {
            "guid": svc_guid,
            "port": port,
            "protocol": e.get("Protocol", "TCP"),
            "host": host
        })

        self.add_node(proc_guid, "Process", {
            "guid": proc_guid,
            "processId": e.get("ProcessId", ""),
            "image": image,
            "processName": os.path.basename(image),
            "host": host,
        })

        # Process BINDS NetworkService (process points to service)
        self.add_edge(proc_guid, svc_guid, rel, {
            "timestamp": e.get("UtcTime", ""),
            "source": e.get("Source", ""),
        })

    def _handle_network_connection(self, e: dict, host: str, rel: str):
        proc_guid = e.get("ProcessGuid")
        dest_ip = e.get("DestinationIp", "")
        dest_port = e.get("DestinationPort", "")

        if not proc_guid or not dest_ip:
            return

        self.add_node(proc_guid, "Process", {
            "guid": proc_guid,
            "image": e.get("Image", ""),
            "host": host,
        })

        if self.inventory.is_internal(dest_ip):
            dest_host = self.inventory.resolve_ip(dest_ip)
            svc_guid = generate_node_guid("NetworkService", dest_host, dest_port)
            # Create NetworkService node for destination
            self.add_node(svc_guid, "NetworkService", {
                "guid": svc_guid,
                "port": dest_port,
                "protocol": e.get("Protocol", "TCP"),
                "host": dest_host
            })
            # For unmanaged devices (PLCs/RTUs), create a single Runtime
            # process to represent the device's firmware/application layer.
            asset_data = self.inventory.get_asset(dest_host)
            if asset_data and not asset_data.get("has_logs", True):
                placeholder_proc_guid = f"runtime://{dest_host}"
                self.add_node(placeholder_proc_guid, "Process", {
                    "guid": placeholder_proc_guid,
                    "processId": "0",
                    "processName": f"{dest_host} Runtime",
                    "image": f"{dest_host} Runtime",
                    "type": "Virtual Process",
                    "host": dest_host,
                })
                # Runtime process BINDS NetworkService
                self.add_edge(placeholder_proc_guid, svc_guid, "BINDS", {
                    "timestamp": e.get("UtcTime", ""),
                    "source": "Inferred",
                })
            target_guid = svc_guid
        else:
            # Skip IPs that should not be modeled as external NetworkEndpoints.
            if self.inventory.should_exclude_external_endpoint_ip(dest_ip):
                return
            # Create NetworkEndpoint for external IP
            external_endpoint_guid = generate_node_guid("NetworkEndpoint", dest_ip)
            self.add_node(external_endpoint_guid, "NetworkEndpoint", {
                "guid": external_endpoint_guid,
                "ipAddress": dest_ip,
                "hostname": dest_ip,
                "zone": "Internet",
                "isExternal": True,
                "isManaged": False
            })
            # Create NetworkService for the external connection (IP:port)
            svc_guid = generate_node_guid("NetworkService", dest_ip, dest_port)
            self.add_node(svc_guid, "NetworkService", {
                "guid": svc_guid,
                "port": dest_port,
                "protocol": e.get("Protocol", "TCP"),
                "host": dest_ip,
                "isExternal": True,
            })
            # NetworkService LISTENS_ON NetworkEndpoint
            self.add_edge(svc_guid, external_endpoint_guid, "LISTENS_ON", {
                "source": "Observed",
            })
            target_guid = svc_guid

        self.add_edge(proc_guid, target_guid, rel, {
            "timestamp": e.get("UtcTime", ""),
            "SourcePort": e.get("SourcePort", ""),
            "DestinationPort": dest_port,
            "Protocol": e.get("Protocol", ""),
            "source": e.get("Source", ""),
            "SourceIp": e.get("SourceIp", ""),
            "DestinationIp": dest_ip,
            "Initiated": e.get("Initiated", ""),
        })

    def _handle_dns_query(self, e: dict, host: str, rel: str):
        proc_guid = e.get("ProcessGuid")
        query_name = e.get("QueryName", "")

        if not proc_guid or not query_name:
            return

        self.add_node(proc_guid, "Process", {
            "guid": proc_guid,
            "image": e.get("Image", ""),
            "host": host,
        })

        dns_guid = generate_node_guid("DNSName", query_name)
        self.add_node(dns_guid, "DNSName", {
            "guid": dns_guid,
            "queryName": query_name,
            "domain": ".".join(query_name.split(".")[-2:]) if "." in query_name else query_name,
        })

        self.add_edge(proc_guid, dns_guid, rel, {
            "timestamp": e.get("UtcTime", ""),
            "source": e.get("Source", ""),
        })

    def _handle_registry_event(self, e: dict, host: str, rel: str):
        proc_guid = e.get("ProcessGuid")
        target_obj = e.get("TargetObject", "")

        if not proc_guid or not target_obj:
            return

        self.add_node(proc_guid, "Process", {
            "guid": proc_guid,
            "image": e.get("Image", ""),
            "host": host,
        })

        reg_guid = generate_node_guid("RegistryKey", host, target_obj)
        self.add_node(reg_guid, "RegistryKey", {
            "guid": reg_guid,
            "keyPath": target_obj,
            "keyName": os.path.basename(target_obj),
            "host": host,
        })

        self.add_edge(proc_guid, reg_guid, rel, {
            "timestamp": e.get("UtcTime", ""),
            "source": e.get("Source", ""),
        })

    def _handle_pipe_event(self, e: dict, host: str, rel: str):
        proc_guid = e.get("ProcessGuid")
        pipe_name = e.get("PipeName", "")

        if not proc_guid or not pipe_name:
            return

        self.add_node(proc_guid, "Process", {
            "guid": proc_guid,
            "image": e.get("Image", ""),
            "host": host,
        })

        pipe_guid = generate_node_guid("Pipe", host, pipe_name)
        self.add_node(pipe_guid, "Pipe", {
            "guid": pipe_guid,
            "pipeName": pipe_name,
            "host": host,
        })

        self.add_edge(proc_guid, pipe_guid, rel, {
            "timestamp": e.get("UtcTime", ""),
            "source": e.get("Source", ""),
        })

    def _handle_process_terminate(self, e: dict, host: str, rel: str):
        proc_guid = e.get("ProcessGuid")
        if not proc_guid:
            return

        self.add_node(proc_guid, "Process", {
            "guid": proc_guid,
            "image": e.get("Image", ""),
            "processId": e.get("ProcessId", ""),
            "host": host,
            "terminatedAt": e.get("UtcTime", ""),
        })

    def _handle_process_interaction(self, e: dict, host: str, rel: str):
        src_guid = e.get("SourceProcessGuid")
        tgt_guid = e.get("TargetProcessGuid")

        if not src_guid or not tgt_guid:
            return

        self.add_node(src_guid, "Process", {
            "guid": src_guid,
            "image": e.get("SourceImage") or e.get("Image", ""),
            "host": host,
        })

        self.add_node(tgt_guid, "Process", {
            "guid": tgt_guid,
            "image": e.get("TargetImage") or e.get("Image", ""),
            "host": host,
        })

        self.add_edge(src_guid, tgt_guid, rel, {
            "timestamp": e.get("UtcTime", ""),
            "source": e.get("Source", ""),
        })

    def _handle_image_load(self, e: dict, host: str, rel: str):
        proc_guid = e.get("ProcessGuid")
        image_loaded = e.get("ImageLoaded", "")

        if not proc_guid or not image_loaded:
            return

        self.add_node(proc_guid, "Process", {
            "guid": proc_guid,
            "image": e.get("Image", ""),
            "host": host,
        })

        file_guid = generate_node_guid("File", host, image_loaded.lower())
        self.add_node(file_guid, "File", {
            "guid": file_guid,
            "path": image_loaded,
            "filename": os.path.basename(image_loaded),
            "extension": os.path.splitext(image_loaded)[1].lower(),
            "host": host,
            "signed": e.get("Signed", ""),
            "signature": e.get("Signature", ""),
        })

        self.add_edge(proc_guid, file_guid, rel, {
            "timestamp": e.get("UtcTime", ""),
            "source": e.get("Source", ""),
        })

    def _handle_service(self, e: dict, host: str, rel: str):
        svc_name = e.get("ServiceName", "")
        proc_guid = e.get("ProcessGuid", "")
        service_cmd = e.get("ServiceCommandLine", "")

        if not svc_name:
            return

        svc_guid = generate_node_guid("Service", host, svc_name)
        self.add_node(svc_guid, "Service", {
            "guid": svc_guid,
            "serviceName": svc_name,
            "displayName": e.get("DisplayName", ""),
            "state": e.get("State", ""),
            "startMode": e.get("StartMode", ""),
            "commandLine": service_cmd,
            "host": host,
        })

        if proc_guid:
            self.add_node(proc_guid, "Process", {
                "guid": proc_guid,
                "processId": e.get("ProcessId", ""),
                "host": host,
            })
            self.add_edge(proc_guid, svc_guid, rel, {
                "timestamp": e.get("UtcTime", ""),
                "source": e.get("Source", ""),
            })

    def _handle_task(self, e: dict, host: str, rel: str):
        task_path = e.get("TaskPath", "")
        task_name = e.get("TaskName", "")

        if not task_path and not task_name:
            return

        task_guid = generate_node_guid("Task", host, task_path or task_name)
        proc_guid = e.get("ProcessGuid")
        user = e.get("UserContext", "")
        user_guid = self.add_user(user, host) if user else ""

        self.add_node(task_guid, "Task", {
            "guid": task_guid,
            "taskName": task_name,
            "taskPath": task_path,
            "enabled": e.get("Enabled", ""),
            "lastRunTime": e.get("LastRunTime", ""),
            "host": host,
        })

        event_id = e.get("EventID")
        if event_id == 91 and user_guid:
            self.add_edge(user_guid, task_guid, rel, {"source": e.get("Source", "")})
        elif event_id == 92 and proc_guid:
            self.add_edge(proc_guid, task_guid, rel, {
                "timestamp": e.get("UtcTime", ""),
                "source": e.get("Source", ""),
                "user": user,
                "taskImage": e.get("Image", ""),
            })
        elif event_id in [93, 94] and proc_guid:
            self.add_edge(proc_guid, task_guid, rel, {
                "timestamp": e.get("UtcTime", ""),
                "source": e.get("Source", ""),
                "user": user,
            })
        elif event_id == 95 and user_guid:
            self.add_edge(user_guid, task_guid, rel, {
                "timestamp": e.get("UtcTime", ""),
                "source": e.get("Source", ""),
            })


# =============================================================================
# EVENT PARSER
# =============================================================================

class EventParser:
    """Parses Velociraptor logs into normalized events"""

    def __init__(self, logs_dir: Path, inventory: AssetInventory, logger: logging.Logger,
                 num_workers: int = 8, use_parallel_io: bool = True):
        self.logs_dir = logs_dir
        self.inventory = inventory
        self.logger = logger
        self.num_workers = num_workers
        self.use_parallel_io = use_parallel_io

    def parse(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Parse all logs and return events and process tracker DataFrames"""
        
        def get_platform_prefix(hostname):
            return "Custom_Linux_" if "LINUX" in hostname.upper() else "Custom_Windows_"

        def load_json_file(file_path: Path) -> list:
            try:
                with open(file_path, encoding='utf-8') as f:
                    content = f.read()
                # Try JSON array first
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    # Fall back to NDJSON (newline-delimited JSON)
                    records = []
                    for line in content.strip().split('\n'):
                        line = line.strip()
                        if line:
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                    return records
            except Exception as e:
                self.logger.warning(f"Failed to load {file_path}: {e}")
                return []

        # Collect files
        self.logger.info("Collecting log files...")
        files_to_load = []
        host_files = {}

        for host_dir in self.logs_dir.iterdir():
            if not host_dir.is_dir():
                continue
            hostname = host_dir.name
            prefix = get_platform_prefix(hostname)
            host_files[hostname] = {}

            for file_type, suffix in LOG_FILES.items():
                file_path = None
                preferred = host_dir / f"{prefix}{suffix}"
                if preferred.exists():
                    file_path = preferred
                else:
                    plain = host_dir / suffix
                    if plain.exists():
                        file_path = plain
                    else:
                        matches = sorted(host_dir.glob(f"*{suffix}"))
                        if matches:
                            file_path = matches[0]

                if file_path is not None:
                    files_to_load.append((hostname, file_type, file_path))
                    host_files[hostname][file_type] = file_path

        self.logger.info(f"Found {len(files_to_load)} log files across {len(host_files)} hosts")

        # Load files in parallel
        self.logger.info("Loading log files...")
        loaded_data = {}

        if self.use_parallel_io and len(files_to_load) > 1:
            with ThreadPoolExecutor(max_workers=min(self.num_workers, len(files_to_load))) as executor:
                futures = {
                    executor.submit(load_json_file, fp): (hn, ft)
                    for hn, ft, fp in files_to_load
                }
                for future in futures:
                    hn, ft = futures[future]
                    loaded_data[(hn, ft)] = future.result()
        else:
            for hn, ft, fp in files_to_load:
                loaded_data[(hn, ft)] = load_json_file(fp)

        total_records = sum(len(v) for v in loaded_data.values())
        self.logger.info(f"Loaded {total_records:,} total records")

        # Build process tracker with hash maps
        self.logger.info("Building process tracker...")
        processes = []
        process_lookup = defaultdict(list)
        pid_lookup = defaultdict(list)
        seen_guids = set()

        for hostname in host_files:
            # PsList
            for proc in loaded_data.get((hostname, "PSLIST"), []):
                if proc is None:
                    continue
                pid = str(proc.get("Pid", ""))
                image = (proc.get("Exe") or proc.get("Name", "")).lower()
                create_time = proc.get("CreateTime") or proc.get("StartTime", "")
                guid = generate_process_guid(hostname, pid, image)

                if guid in seen_guids:
                    continue
                seen_guids.add(guid)

                creation_dt = parse_timestamp_fast(create_time)
                processes.append({
                    "host": hostname, "pid": pid, "guid": guid,
                    "creation_time": create_time, "image": image,
                    "command_line": proc.get("CommandLine", ""),
                    "user": proc.get("Username", ""),
                    "parent_pid": str(proc.get("Ppid", "")),
                    "source": "PsList"
                })
                process_lookup[(hostname, pid, image)].append((creation_dt, guid))
                pid_lookup[(hostname, pid)].append((creation_dt, guid, image))

            # Sysmon ProcessCreate/Terminate
            for evt in loaded_data.get((hostname, "SYSMON"), []):
                if evt is None:
                    continue
                eid = evt.get("EID")
                if eid is None:
                    continue
                eid = int(eid)

                if eid in (1, 5):
                    event_data = evt.get("EventData", {})
                    pid = str(event_data.get("ProcessId", ""))
                    image = event_data.get("Image", "").lower()
                    create_time = evt.get("TimeStamp", "") if eid == 1 else "1970-01-01T00:00:00Z"
                    guid = generate_process_guid(hostname, pid, image)

                    if guid in seen_guids:
                        continue
                    seen_guids.add(guid)

                    creation_dt = parse_timestamp_fast(create_time)
                    processes.append({
                        "host": hostname, "pid": pid, "guid": guid,
                        "creation_time": create_time, "image": image,
                        "command_line": event_data.get("CommandLine", "") if eid == 1 else "",
                        "user": event_data.get("User", ""),
                        "parent_pid": str(event_data.get("ParentProcessId", "")) if eid == 1 else "",
                        "source": "Sysmon" if eid == 1 else "Sysmon-Terminate"
                    })
                    process_lookup[(hostname, pid, image)].append((creation_dt, guid))
                    pid_lookup[(hostname, pid)].append((creation_dt, guid, image))

        # Sort lookup lists
        for key in process_lookup:
            process_lookup[key].sort(key=lambda x: (x[0] or datetime.min))
        for key in pid_lookup:
            pid_lookup[key].sort(key=lambda x: (x[0] or datetime.min))

        process_tracker = pd.DataFrame(processes)
        self.logger.info(f"Process tracker: {len(process_tracker):,} instances")

        # Fast GUID resolver
        def resolve_guid(host, pid, image=None, timestamp=None):
            if not pid:
                return None
            pid = str(pid)

            if image:
                candidates = process_lookup.get((host, pid, image.lower()))
                if candidates:
                    if len(candidates) == 1:
                        return candidates[0][1]
                    if timestamp:
                        event_dt = parse_timestamp_fast(timestamp)
                        if event_dt:
                            best = None
                            for dt, guid in candidates:
                                if dt is None or dt <= event_dt:
                                    best = guid
                                else:
                                    break
                            return best or candidates[-1][1]
                    return candidates[-1][1]

            candidates = pid_lookup.get((host, pid))
            if not candidates:
                return None
            if len(candidates) == 1:
                return candidates[0][1]
            if timestamp:
                event_dt = parse_timestamp_fast(timestamp)
                if event_dt:
                    best = None
                    for dt, guid, _ in candidates:
                        if dt is None or dt <= event_dt:
                            best = guid
                        else:
                            break
                    return best or candidates[-1][1]
            return candidates[-1][1]

        # Parse events
        self.logger.info("Parsing events...")
        events = []
        FILE_READ_MASK = 0x0001 | 0x0008 | 0x0080
        FILE_WRITE_MASK = 0x0002 | 0x0004 | 0x0010 | 0x0100

        for hostname in host_files:
            # Sysmon events
            for evt in loaded_data.get((hostname, "SYSMON"), []):
                if evt is None:
                    continue
                eid = evt.get("EID")
                if eid is None:
                    continue
                clean_eid = SYSMON_EVENT_MAP.get(int(eid))
                if not clean_eid:
                    continue

                timestamp = evt.get("TimeStamp", "")
                event = {
                    "EventID": clean_eid,
                    "OriginalEventID": int(eid),
                    "Computer": hostname,
                    "UtcTime": timestamp,
                    "Source": "Sysmon",
                }

                if "EventData" in evt:
                    event.update(evt["EventData"])

                if "Initiated" in event:
                    if event["Initiated"].lower() == "false":
                        dest_ip = event.get("DestinationIp", event.get("DestinationIP", ""))
                        if hostname == self.inventory.resolve_ip(dest_ip):
                            # Genuine incoming: DestinationIP is this machine — convert to listener event.
                            event = {
                                "EventID": 31, "Host": hostname, "UtcTime": timestamp,
                                "Source": "Sysmon", "ProcessId": event["ProcessId"],
                                "ProcessGuid": resolve_guid(hostname, event["ProcessId"], event.get("Image", ""), timestamp),
                                "Image": event.get("Image", ""), "Protocol": event.get("Protocol", "TCP"),
                                "DestinationPort": str(event.get("DestinationPort", "")),
                                "Address": event.get("Address", "0.0.0.0"),
                            }
                            events.append(event)
                        # else: DestinationIP is a remote host — Sysmon mislabeled this as
                        # Initiated:false (e.g. raw socket usage by malware). Fall through
                        # so it is processed as a normal outgoing EID 3 connection.

                if "ProcessId" in event:
                    event["ProcessGuid"] = resolve_guid(hostname, event["ProcessId"], event.get("Image", ""), timestamp)
                if "ParentProcessId" in event:
                    event["ParentProcessGuid"] = resolve_guid(hostname, event["ParentProcessId"], event.get("ParentImage", ""), timestamp)
                if "SourceProcessId" in event:
                    event["SourceProcessGuid"] = resolve_guid(hostname, event["SourceProcessId"], event.get("SourceImage", ""), timestamp)
                if "TargetProcessId" in event:
                    event["TargetProcessGuid"] = resolve_guid(hostname, event["TargetProcessId"], event.get("TargetImage", ""), timestamp)

                events.append(event)

            # FileIO events
            for evt in loaded_data.get((hostname, "FILEIO"), []):
                if evt is None:
                    continue
                access_mask = evt.get("AccessMask", 0)
                if access_mask & FILE_WRITE_MASK:
                    event_id = 17
                elif access_mask & FILE_READ_MASK:
                    event_id = 16
                else:
                    continue

                pid = evt.get("PID")
                ts = evt.get("TimeStamp", 0)
                timestamp = datetime.fromtimestamp(ts).isoformat() if ts else ""
                image = evt.get("ProcessName", "")

                events.append({
                    "EventID": event_id, "Computer": hostname, "UtcTime": timestamp,
                    "Source": "FileIO", "ProcessId": str(pid),
                    "ProcessGuid": resolve_guid(hostname, pid, image, timestamp),
                    "Image": image, "TargetFilename": evt.get("ObjectName", ""),
                })

            # PsList events
            for proc in loaded_data.get((hostname, "PSLIST"), []):
                if proc is None:
                    continue
                pid = str(proc.get("Pid", ""))
                ppid = str(proc.get("Ppid", ""))
                create_time = proc.get("CreateTime") or proc.get("StartTime", "")
                image = proc.get("Exe") or proc.get("Name", "")

                events.append({
                    "EventID": 1, "Host": hostname, "UtcTime": create_time,
                    "Source": "PsList", "ProcessId": pid,
                    "ProcessGuid": resolve_guid(hostname, pid, image, create_time),
                    "Image": image, "CommandLine": proc.get("CommandLine", ""),
                    "User": proc.get("Username", ""), "ParentProcessId": ppid,
                    "ParentProcessGuid": resolve_guid(hostname, ppid, "", create_time),
                })

            # Listening events
            for svc in loaded_data.get((hostname, "LISTENING"), []):
                if svc is None:
                    continue
                pid = str(svc.get("Pid", ""))
                timestamp = svc.get("CreateTime", "")
                image = svc.get("Name", "")

                events.append({
                    "EventID": 31, "Host": hostname, "UtcTime": timestamp,
                    "Source": "ListeningTable", "ProcessId": pid,
                    "ProcessGuid": resolve_guid(hostname, pid, image, timestamp),
                    "Image": image, "Protocol": svc.get("Protocol", "TCP"),
                    "DestinationPort": str(svc.get("Port", "")),
                    "Address": svc.get("Address", "0.0.0.0"),
                })

            # Services events
            for svc in loaded_data.get((hostname, "SERVICES"), []):
                if svc is None:
                    continue
                pid = svc.get("PID")
                action = svc.get("Action", "")
                event_id = {"Start Service": 82, "Stop Service": 83, "Modify Service": 84}.get(action)
                if not event_id or not pid or pid == 0:
                    continue

                events.append({
                    "EventID": event_id, "Host": hostname,
                    "UtcTime": svc.get("TimeStamp", ""), "Source": "Services",
                    "ServiceName": svc.get("ServiceName") or svc.get("Name", ""),
                    "DisplayName": svc.get("DisplayName", ""),
                    "ProcessId": str(pid),
                    "ProcessGuid": resolve_guid(hostname, pid, "", svc.get("TimeStamp", "")),
                    "ServiceCommandLine": svc.get("ServiceCommandLine") or svc.get("PathName", ""),
                    "State": action, "StartMode": svc.get("Startup") or svc.get("StartMode", ""),
                })

            # Task events
            for task in loaded_data.get((hostname, "TASKS"), []):
                if task is None:
                    continue
                action = task.get("Action", "")
                timestamp = task.get("TimeStamp", "")
                task_name = task.get("TaskName", "")
                user_context = task.get("UserContext", "")
                path = task.get("Path", "")
                pid = task.get("PID")

                event_map = {
                    "Task Process Created": 92, "Task Registered": 93,
                    "Task Deleted": 94, "Task Disabled": 95
                }
                event_id = event_map.get(action)
                if not event_id:
                    continue

                event = {
                    "EventID": event_id, "Host": hostname, "UtcTime": timestamp,
                    "Source": "TaskMonitor", "TaskName": task_name,
                    "UserContext": user_context,
                }
                if event_id == 92:
                    event.update({
                        "ProcessId": str(pid),
                        "ProcessGuid": resolve_guid(hostname, pid, path, timestamp),
                        "Image": path,
                    })
                elif event_id == 93:
                    event["Path"] = path
                events.append(event)

        events_df = pd.DataFrame(events).fillna("")
        for col in ["EventID", "Host", "Source"]:
            if col in events_df.columns:
                events_df[col] = events_df[col].astype("category")

        self.logger.info(f"Parsed {len(events_df):,} events")
        return events_df, process_tracker


# =============================================================================
# NEO4J EXPORTER
# =============================================================================

class Neo4jExporter:
    """Generates Neo4j Cypher import script"""

    def __init__(self, inventory: AssetInventory, logger: logging.Logger):
        self.inventory = inventory
        self.logger = logger

    @staticmethod
    def escape_cypher(value) -> str:
        if value is None or value == "":
            return ""
        return str(value).replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")

    def format_props(self, props: dict) -> str:
        items = []
        for k, v in props.items():
            if v is None or v == "":
                continue
            key = "".join(c for c in k if c.isalnum() or c == "_")
            if not key:
                continue

            if isinstance(v, str) and len(v) >= 19 and ("T" in v or "-" in v[:10]):
                try:
                    dt = datetime.fromisoformat(v.replace("Z", "+00:00").split(".")[0])
                    items.append(f"{key}: datetime('{dt.isoformat()}')")
                    continue
                except:
                    pass

            if isinstance(v, (int, float)):
                items.append(f"{key}: {v}")
            elif isinstance(v, bool):
                items.append(f"{key}: {str(v).lower()}")
            elif isinstance(v, list):
                formatted = [f"'{self.escape_cypher(str(i))}'" if isinstance(i, str) else str(i) for i in v]
                items.append(f"{key}: [{', '.join(formatted)}]")
            else:
                items.append(f"{key}: '{self.escape_cypher(v)}'")

        return "{" + ", ".join(items) + "}"

    def export(self, builder: GraphBuilder, output_file: Path):
        self.logger.info(f"Exporting to {output_file}")

        with open(output_file, "w", encoding="utf-8") as f:
            # Header
            f.write("// " + "=" * 80 + "\n")
            f.write("// ICS PROVENANCE GRAPH - Neo4j Import Script\n")
            f.write(f"// Generated: {datetime.now().isoformat()}\n")
            f.write(f"// Nodes: {len(builder.nodes)}, Edges: {sum(len(v) for v in builder.edges.values())}\n")
            f.write("// " + "=" * 80 + "\n\n")

            # Constraints
            f.write("// CONSTRAINTS\n")
            for node_type, config in NODE_TYPES.items():
                f.write(f"CREATE CONSTRAINT {node_type.lower()}_guid IF NOT EXISTS FOR (n:{config['label']}) REQUIRE n.{config['pk']} IS UNIQUE;\n")
            f.write("\n")

            # NetworkEndpoint nodes (internal assets)
            f.write("// NETWORK ENDPOINT NODES (INTERNAL ASSETS)\n")
            for hostname in sorted(self.inventory.assets.keys()):
                asset = self.inventory.get_asset(hostname)
                asset_guid = generate_node_guid("NetworkEndpoint", hostname)
                props = {
                    "guid": asset_guid, "hostname": hostname,
                    "ipAddresses": asset.get("ip_addresses", []),
                    "role": asset.get("role", ""), "zone": asset.get("zone", ""),
                    "os": asset.get("os", ""), "description": asset.get("description", ""),
                    "isManaged": str(asset.get("is_managed", False)).lower(),
                    "isExternal": False,
                }
                f.write(f"MERGE (n:NetworkEndpoint {self.format_props(props)});\n")
            f.write("\n")

            # External NetworkEndpoint nodes (Internet destinations)
            external_nodes = [(nid, nd) for nid, nd in builder.nodes.items() 
                              if nd["type"] == "NetworkEndpoint" and nd["props"].get("isExternal")]
            if external_nodes:
                f.write("// NETWORK ENDPOINT NODES (EXTERNAL/INTERNET)\n")
                for node_id, node_data in external_nodes:
                    props = node_data["props"]
                    if not props.get("guid"):
                        props["guid"] = node_id
                    f.write(f"MERGE (n:NetworkEndpoint {self.format_props(props)});\n")
                f.write("\n")

            # Other nodes by type
            for node_type in ["User", "Process", "File", "Service", "Task", "NetworkService", "DNSName", "RegistryKey", "Pipe"]:
                nodes = [(nid, nd) for nid, nd in builder.nodes.items() if nd["type"] == node_type]
                if nodes:
                    f.write(f"// {node_type.upper()} NODES\n")
                    for node_id, node_data in nodes:
                        props = node_data["props"]
                        if not props.get("guid"):
                            props["guid"] = node_id
                        f.write(f"MERGE (n:{node_type} {self.format_props(props)});\n")
                    f.write("\n")

            # Structural relationships
            f.write("// STRUCTURAL RELATIONSHIPS\n")
            f.write("MATCH (p:Process), (n:NetworkEndpoint) WHERE p.host = n.hostname AND n.isExternal = false MERGE (p)-[:RUN_ON]->(n);\n")
            f.write("MATCH (f:File), (n:NetworkEndpoint) WHERE f.host = n.hostname AND n.isExternal = false MERGE (f)-[:EXIST_ON]->(n);\n")
            f.write("MATCH (r:RegistryKey), (n:NetworkEndpoint) WHERE r.host = n.hostname AND n.isExternal = false MERGE (r)-[:EXIST_ON]->(n);\n")
            f.write("MATCH (ns:NetworkService), (n:NetworkEndpoint) WHERE ns.host = n.hostname AND n.isExternal = false MERGE (ns)-[:LISTENS_ON]->(n);\n")
            f.write("MATCH (s:Service), (n:NetworkEndpoint) WHERE s.host = n.hostname AND n.isExternal = false MERGE (s)-[:INSTALLED_ON]->(n);\n")
            f.write("MATCH (t:Task), (n:NetworkEndpoint) WHERE t.host = n.hostname AND n.isExternal = false MERGE (t)-[:SCHEDULED_ON]->(n);\n")
            f.write("MATCH (pi:Pipe), (n:NetworkEndpoint) WHERE pi.host = n.hostname AND n.isExternal = false MERGE (pi)-[:CREATED_ON]->(n);\n")
            f.write("MATCH (p:Process), (u:User) WHERE p.host = u.host AND p.user = u.username MERGE (p)-[:RUN_AS]->(u);\n\n")

            # Event relationships
            f.write("// EVENT RELATIONSHIPS\n")
            for (from_id, to_id, rel_type), edge_list in builder.edges.items():
                from_node = builder.nodes.get(from_id, {})
                to_node = builder.nodes.get(to_id, {})

                if not from_node or not to_node:
                    continue

                from_label = NODE_TYPES[from_node["type"]]["label"]
                to_label = NODE_TYPES[to_node["type"]]["label"]
                from_guid = from_node["props"].get("guid", from_id)
                to_guid = to_node["props"].get("guid", to_id)

                timestamps = sorted([e["timestamp"] for e in edge_list if e.get("timestamp")])
                sources = list(set([e.get("source", "") for e in edge_list if e.get("source")]))

                rel_props = {"count": len(edge_list), "source": ", ".join(sources) if sources else ""}
                if timestamps:
                    rel_props["timestamp"] = timestamps[-1]
                    if len(timestamps) > 1:
                        rel_props["firstSeen"] = timestamps[0]
                        rel_props["lastSeen"] = timestamps[-1]

                # For network connection edges, preserve session metadata for PCAP correlation.
                # Keep backward compatibility with older relation names.
                if rel_type in {"ESTABLISH_CONNECTION", "CONNECT_TO"}:
                    def _most_common_non_empty(*keys):
                        values = []
                        for edge in edge_list:
                            for key in keys:
                                value = edge.get(key)
                                if value in (None, ""):
                                    continue
                                values.append(str(value))
                                break
                        if not values:
                            return None
                        return Counter(values).most_common(1)[0][0]

                    source_ip = _most_common_non_empty("SourceIp", "sourceIp", "sourceIP")
                    destination_ip = _most_common_non_empty("DestinationIp", "destinationIp", "destinationIP")
                    source_port = _most_common_non_empty("SourcePort", "sourcePort")
                    destination_port = _most_common_non_empty("DestinationPort", "destinationPort")
                    protocol = _most_common_non_empty("Protocol", "protocol")
                    initiated = _most_common_non_empty("Initiated", "initiated")

                    if source_ip:
                        rel_props["SourceIp"] = source_ip
                    if destination_ip:
                        rel_props["DestinationIp"] = destination_ip
                    if source_port:
                        rel_props["SourcePort"] = source_port
                    if destination_port:
                        rel_props["DestinationPort"] = destination_port
                    if protocol:
                        rel_props["Protocol"] = protocol
                    if initiated:
                        rel_props["Initiated"] = initiated

                    session_data = []
                    for e in edge_list:
                        src_port = e.get("SourcePort") or e.get("sourcePort")
                        ts = e.get("timestamp")
                        if src_port and ts:
                            try:
                                port_int = int(src_port)
                                # Convert ISO timestamp to epoch float for PCAP compatibility
                                ts_dt = parse_timestamp_fast(ts)
                                if ts_dt:
                                    epoch_ts = ts_dt.timestamp()
                                    session_data.append((epoch_ts, port_int))
                            except (ValueError, TypeError):
                                pass

                    if session_data:
                        # Sort by timestamp and extract parallel arrays
                        session_data.sort(key=lambda x: x[0])
                        rel_props["sessionPorts"] = [s[1] for s in session_data]
                        rel_props["sessionTimestamps"] = [s[0] for s in session_data]

                f.write(
                    f"MATCH (a:{from_label} {{guid: '{self.escape_cypher(from_guid)}'}}), "
                    f"(b:{to_label} {{guid: '{self.escape_cypher(to_guid)}'}}) "
                    f"MERGE (a)-[r:{rel_type}]->(b) "
                    f"ON CREATE SET r = {self.format_props(rel_props)} "
                    f"ON MATCH SET r.count = r.count + {len(edge_list)};\n"
                )

            f.write("\n// EXPORT COMPLETE\n")

        total_edges = sum(len(v) for v in builder.edges.values())
        self.logger.info(f"Export complete: {len(builder.nodes):,} nodes, {total_edges:,} edges")


# =============================================================================
# MAIN PIPELINE
# =============================================================================

def build_provenance_graph(
    logs_dir: Path,
    assets_file: Path,
    output_file: Path,
    use_cache: bool = True,
    num_workers: int = 8,
    verbose: bool = False
) -> dict:
    """Build provenance graph from Velociraptor logs"""

    # Setup logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger("build_graph")

    pipeline_start = time.time()

    # Load asset inventory
    logger.info("=" * 60)
    logger.info("LOADING ASSETS")
    logger.info("=" * 60)
    inventory = AssetInventory(assets_file, logger)

    # Parse events
    logger.info("=" * 60)
    logger.info("PARSING EVENTS")
    logger.info("=" * 60)

    cache_file = logs_dir / "event_cache.pkl"
    events_df = None
    process_tracker = None

    if use_cache and cache_file.exists():
        json_files = list(logs_dir.glob("**/*.json"))
        if json_files:
            cache_mtime = cache_file.stat().st_mtime
            newest_log = max(f.stat().st_mtime for f in json_files)
            if cache_mtime > newest_log:
                logger.info("Loading from cache...")
                try:
                    cached = pd.read_pickle(cache_file)
                    if isinstance(cached, tuple) and len(cached) == 2:
                        events_df, process_tracker = cached
                except:
                    pass

    if events_df is None:
        parser = EventParser(logs_dir, inventory, logger, num_workers)
        events_df, process_tracker = parser.parse()

        if use_cache and not events_df.empty:
            logger.info("Saving to cache...")
            pd.to_pickle((events_df, process_tracker), cache_file)

    logger.info(f"Events: {len(events_df):,}, Processes: {len(process_tracker):,}")

    # Build graph
    logger.info("=" * 60)
    logger.info("BUILDING GRAPH")
    logger.info("=" * 60)

    phase_start = time.time()
    builder = GraphBuilder(inventory)

    events_list = events_df.to_dict('records')
    chunk_size = 10000
    chunks = [events_list[i:i + chunk_size] for i in range(0, len(events_list), chunk_size)]

    logger.info(f"Processing {len(events_list):,} events in {len(chunks)} batches")

    def process_batch(batch):
        local_builder = GraphBuilder(inventory)
        for event in batch:
            local_builder.process_event(event)
        return local_builder

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        batch_builders = list(executor.map(process_batch, chunks))

    # Merge results
    for batch_builder in batch_builders:
        for node_id, node_data in batch_builder.nodes.items():
            if node_id in builder.nodes:
                builder.nodes[node_id]["props"].update(node_data["props"])
            else:
                builder.nodes[node_id] = node_data
        for edge_key, edge_list in batch_builder.edges.items():
            builder.edges[edge_key].extend(edge_list)
        builder.users.update(batch_builder.users)
        builder.assets.update(batch_builder.assets)

    graph_time = time.time() - phase_start
    total_edges = sum(len(v) for v in builder.edges.values())
    logger.info(f"Graph built in {graph_time:.2f}s: {len(builder.nodes):,} nodes, {total_edges:,} edges")

    # Export
    logger.info("=" * 60)
    logger.info("EXPORTING TO NEO4J")
    logger.info("=" * 60)

    exporter = Neo4jExporter(inventory, logger)
    exporter.export(builder, output_file)

    # Summary
    total_time = time.time() - pipeline_start
    logger.info("=" * 60)
    logger.info("PIPELINE COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Total time: {total_time:.2f}s")
    logger.info(f"Processing rate: {len(events_df) / total_time:,.0f} events/sec")
    logger.info(f"Output: {output_file}")

    return {
        "events": len(events_df),
        "nodes": len(builder.nodes),
        "edges": total_edges,
        "time": total_time,
        "output": str(output_file),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Build ICS provenance graph from Velociraptor logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s
    %(prog)s --logs ./logs --assets ./assets.yaml --output ./graph.cypher
    %(prog)s --no-cache --verbose
        """,
    )

    parser.add_argument(
        "--logs", "-l",
        default="./logs",
        help="Directory containing Velociraptor logs (default: ./logs)"
    )

    parser.add_argument(
        "--assets", "-a",
        default="./assets.yaml",
        help="Path to assets YAML file (default: ./assets.yaml)"
    )

    parser.add_argument(
        "--output", "-o",
        default="./neo4j_export.cypher",
        help="Output Cypher file path (default: ./neo4j_export.cypher)"
    )

    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable event caching"
    )

    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=8,
        help="Number of parallel workers (default: 8)"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Validate paths
    logs_dir = Path(args.logs)
    assets_file = Path(args.assets)
    output_file = Path(args.output)

    if not logs_dir.exists():
        logging.error(f"Logs directory not found: {logs_dir}")
        sys.exit(1)

    if not assets_file.exists():
        logging.error(f"Assets file not found: {assets_file}")
        sys.exit(1)

    # Run pipeline
    try:
        summary = build_provenance_graph(
            logs_dir=logs_dir,
            assets_file=assets_file,
            output_file=output_file,
            use_cache=not args.no_cache,
            num_workers=args.workers,
            verbose=args.verbose,
        )

        # Print summary
        print(f"\n✅ Graph built successfully!")
        print(f"   Events: {summary['events']:,}")
        print(f"   Nodes: {summary['nodes']:,}")
        print(f"   Edges: {summary['edges']:,}")
        print(f"   Time: {summary['time']:.2f}s")
        print(f"   Output: {summary['output']}")

    except Exception as e:
        logging.error(f"Pipeline failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
