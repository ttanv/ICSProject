"""Modbus protocol handler for grouped augmentation artifacts."""

from __future__ import annotations

import logging
import multiprocessing as mp
import os
from typing import List, Optional, Tuple

from tqdm import tqdm

from ..models import ConnectionKey
from ..grouping import ModbusGroup, group_modbus_connections
from .base import ProtocolBuildResult
from .context import ProtocolBuildContext

logger = logging.getLogger(__name__)


# Module-level state inherited by fork-based worker processes via copy-on-write.
# Set before pool creation; read-only in workers.
_SHARED_GROUPS: Optional[List[ModbusGroup]] = None
_SHARED_AUGMENTOR = None


def _resolve_worker_count() -> int:
    """Decide how many parallel workers to use for Modbus group compute.

    Defaults to a conservative count tied to CPU count. Set
    NETWORK_AUG_MODBUS_WORKERS=1 to force sequential execution.
    """
    raw = os.environ.get("NETWORK_AUG_MODBUS_WORKERS")
    if raw is not None:
        try:
            return max(1, int(raw))
        except ValueError:
            logger.warning("Invalid NETWORK_AUG_MODBUS_WORKERS=%r; falling back to auto", raw)
    return min(8, max(1, (os.cpu_count() or 2) - 1))


class ModbusProtocolHandler:
    """Protocol plugin that emits Modbus-specific graph artifacts."""

    name = "modbus"

    def build_artifacts(self, context: ProtocolBuildContext) -> ProtocolBuildResult:
        modbus_groups, modbus_consumed = group_modbus_connections(context.connections)
        relationship_count = 0

        asset_ips = getattr(context.augmentor, "_asset_ips", set())
        policy = context.augmentor.config.policy

        # Pre-filter so only eligible groups reach the heavy compute phase.
        candidates: List[Tuple[ModbusGroup, ConnectionKey]] = []
        for group in modbus_groups:
            if all(
                cid in context.base_connection_ids or cid in context.correlated_cids
                for cid in group.canonical_ids()
            ):
                continue
            if asset_ips and group.client_ip not in asset_ips and group.server_ip not in asset_ips:
                continue
            connection_key = ConnectionKey(
                src_ip=group.client_ip,
                src_port=0,
                dst_ip=group.server_ip,
                dst_port=group.service_port,
                protocol=group.protocol,
            )
            if (
                policy.is_broadcast_or_multicast(connection_key.src_ip)
                or policy.is_broadcast_or_multicast(connection_key.dst_ip)
            ):
                continue
            if policy.is_outer(connection_key.src_ip) and policy.is_outer(connection_key.dst_ip):
                continue
            candidates.append((group, connection_key))

        workers = _resolve_worker_count()
        use_processes = workers > 1 and len(candidates) > 1 and hasattr(os, "fork")

        compute_fn = context.augmentor._compute_modbus_group_payload

        # Keep payloads aligned with candidates by index for a deterministic apply order.
        payloads: List[Optional[object]] = [None] * len(candidates)

        if use_processes:
            global _SHARED_GROUPS, _SHARED_AUGMENTOR
            _SHARED_GROUPS = [g for g, _ in candidates]
            _SHARED_AUGMENTOR = context.augmentor
            try:
                ctx = mp.get_context("fork")
                with ctx.Pool(processes=workers) as pool:
                    tasks = [(i, key) for i, (_, key) in enumerate(candidates)]
                    iterable = pool.imap_unordered(_worker_compute_indexed, tasks, chunksize=1)
                    bar = (
                        tqdm(total=len(tasks), desc="Processing Modbus groups", unit="group")
                        if context.show_progress
                        else None
                    )
                    try:
                        for idx, payload in iterable:
                            payloads[idx] = payload
                            if bar is not None:
                                bar.update(1)
                    finally:
                        if bar is not None:
                            bar.close()
            finally:
                _SHARED_GROUPS = None
                _SHARED_AUGMENTOR = None
        else:
            iterator = enumerate(candidates)
            if context.show_progress:
                iterator = tqdm(iterator, total=len(candidates), desc="Processing Modbus groups", unit="group")
            for i, (group, key) in iterator:
                payloads[i] = compute_fn(group, key)

        for i, (group, _key) in enumerate(candidates):
            payload = payloads[i]
            if payload is None:
                continue
            before_count = len(context.relationship_statements)
            context.augmentor._apply_modbus_group_payload(
                payload=payload,
                group=group,
                asset_statements=context.asset_statements,
                service_statements=context.service_statements,
                host_statements=context.host_statements,
                register_statements=context.register_statements,
                process_statements=context.process_statements,
                runs_statements=context.runs_statements,
                relationship_statements=context.relationship_statements,
                process_register_statements=context.process_register_statements,
                telemetry_index=context.telemetry_index,
            )
            relationship_count += max(len(context.relationship_statements) - before_count, 0)
            context.processed_cids.update(group.canonical_ids())

        context.processed_cids.update(modbus_consumed)
        return ProtocolBuildResult(
            relationship_count=relationship_count,
            consumed_cids=modbus_consumed,
        )


def _worker_compute_indexed(args: Tuple[int, ConnectionKey]) -> Tuple[int, object]:
    """Index-preserving worker: returns (task_idx, payload) so the caller can align results to candidates."""
    idx, connection_key = args
    group = _SHARED_GROUPS[idx]
    payload = _SHARED_AUGMENTOR._compute_modbus_group_payload(group, connection_key)
    return idx, payload
