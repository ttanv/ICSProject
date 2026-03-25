"""IEC 61131-3 Structured Text parser for invariant enhancement.

Extracts AT-addressed variables, LIMIT bounds, and CASE-based FSM structure.
Uses blark (Lark-based IEC 61131-3 parser) with regex fallback.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# AT address patterns: %IW<n>, %QW<n>, %MW<n>, %QX<n>.<b>
_AT_REGEX = re.compile(
    r"(\w+)\s+AT\s+%([IQM][WX])(\d+)(?:\.(\d+))?\s*:\s*(\w+)",
    re.IGNORECASE,
)

# LIMIT(low, expr, high) calls
_LIMIT_REGEX = re.compile(
    r"(\w+)\s*:=\s*LIMIT\(\s*([^,]+?)\s*,\s*([^,]+?)\s*,\s*([^)]+?)\s*\)",
    re.IGNORECASE,
)

# CASE <var> OF ... END_CASE
_CASE_REGEX = re.compile(
    r"CASE\s+(\w+)\s+OF\s+(.*?)END_CASE",
    re.IGNORECASE | re.DOTALL,
)

# Case label: integer literal followed by colon
_CASE_LABEL_REGEX = re.compile(r"^\s*(\d+)\s*:", re.MULTILINE)


@dataclass
class STVariable:
    """A variable with an AT address declaration."""

    name: str
    at_type: str  # "IW", "QW", "MW", "QX"
    at_address: int
    at_bit: Optional[int]  # Only for QX
    datatype: str
    resolved_register: int  # Computed Modbus register address


@dataclass
class STLimitBound:
    """A LIMIT(low, expr, high) call with resolved constant bounds."""

    variable: str  # The output variable assigned the LIMIT result
    expression: str  # The middle expression
    low: Optional[float]  # Resolved low bound (None if non-constant)
    high: Optional[float]  # Resolved high bound (None if non-constant)


@dataclass
class STFsmInfo:
    """FSM structure extracted from CASE statement."""

    state_variable: str
    state_register: Optional[int]  # Register address if AT-addressed
    state_ids: List[int]  # Integer labels from CASE branches


@dataclass
class STProgramInfo:
    """Parsed information from an ST file."""

    variables: List[STVariable] = field(default_factory=list)
    limit_bounds: List[STLimitBound] = field(default_factory=list)
    fsm: Optional[STFsmInfo] = None

    @property
    def has_fsm(self) -> bool:
        return self.fsm is not None


def _resolve_register(
    at_type: str, at_address: int, at_bit: Optional[int], offset: int
) -> int:
    """Convert AT address to Modbus register address."""
    if at_type.upper() == "QX":
        # Coil: address * 8 + bit
        return at_address * 8 + (at_bit or 0) + offset
    return at_address + offset


def _resolve_constant(
    expr: str, constants: Dict[str, float]
) -> Optional[float]:
    """Try to resolve an expression to a constant float value."""
    expr = expr.strip()
    # Direct numeric literal
    try:
        return float(expr)
    except ValueError:
        pass
    # Known constant name
    if expr in constants:
        return constants[expr]
    return None


def _extract_constants(source: str) -> Dict[str, float]:
    """Extract simple constant assignments from ST source.

    Handles patterns like: name : REAL := 100.0;
    """
    constants: Dict[str, float] = {}
    pattern = re.compile(
        r"(\w+)\s*:\s*\w+\s*:=\s*([+-]?\d+(?:\.\d+)?)\s*;",
    )
    for match in pattern.finditer(source):
        name, value = match.group(1), match.group(2)
        try:
            constants[name] = float(value)
        except ValueError:
            pass
    return constants


def _parse_with_regex(source: str, register_offset: int = 0) -> STProgramInfo:
    """Regex-based fallback parser for ST files."""
    info = STProgramInfo()
    constants = _extract_constants(source)

    # Extract AT-addressed variables
    for match in _AT_REGEX.finditer(source):
        name = match.group(1)
        at_type = match.group(2).upper()
        at_address = int(match.group(3))
        at_bit = int(match.group(4)) if match.group(4) else None
        datatype = match.group(5)

        resolved = _resolve_register(at_type, at_address, at_bit, register_offset)
        info.variables.append(
            STVariable(
                name=name,
                at_type=at_type,
                at_address=at_address,
                at_bit=at_bit,
                datatype=datatype,
                resolved_register=resolved,
            )
        )

    # Extract LIMIT calls
    for match in _LIMIT_REGEX.finditer(source):
        variable = match.group(1)
        low_expr = match.group(2)
        expression = match.group(3)
        high_expr = match.group(4)

        low = _resolve_constant(low_expr, constants)
        high = _resolve_constant(high_expr, constants)

        info.limit_bounds.append(
            STLimitBound(
                variable=variable,
                expression=expression,
                low=low,
                high=high,
            )
        )

    # Extract CASE-based FSM
    case_match = _CASE_REGEX.search(source)
    if case_match:
        state_var = case_match.group(1)
        case_body = case_match.group(2)

        state_ids = [
            int(m.group(1)) for m in _CASE_LABEL_REGEX.finditer(case_body)
        ]

        if state_ids:
            # Check if state variable has an AT address
            state_register = None
            for var in info.variables:
                if var.name == state_var:
                    state_register = var.resolved_register
                    break

            info.fsm = STFsmInfo(
                state_variable=state_var,
                state_register=state_register,
                state_ids=state_ids,
            )

    logger.info(
        "Regex parser: %d variables, %d LIMIT bounds, FSM=%s",
        len(info.variables),
        len(info.limit_bounds),
        info.has_fsm,
    )
    return info


def _parse_with_blark(source: str, register_offset: int = 0) -> STProgramInfo:
    """Parse ST file using blark library for robust AST-based extraction."""
    try:
        import blark
    except ImportError:
        raise ImportError(
            "blark is required for AST-based ST parsing. "
            "Install it with: pip install blark\n"
            "Falling back to regex parsing is also supported."
        )

    info = STProgramInfo()
    constants = _extract_constants(source)

    try:
        parsed = blark.parse(source)
    except Exception as exc:
        logger.warning("blark failed to parse ST file: %s, falling back to regex", exc)
        return _parse_with_regex(source, register_offset)

    # Walk the AST for AT-addressed variable declarations
    source_text = source  # Use regex on source alongside AST
    for match in _AT_REGEX.finditer(source_text):
        name = match.group(1)
        at_type = match.group(2).upper()
        at_address = int(match.group(3))
        at_bit = int(match.group(4)) if match.group(4) else None
        datatype = match.group(5)

        resolved = _resolve_register(at_type, at_address, at_bit, register_offset)
        info.variables.append(
            STVariable(
                name=name,
                at_type=at_type,
                at_address=at_address,
                at_bit=at_bit,
                datatype=datatype,
                resolved_register=resolved,
            )
        )

    # LIMIT bounds from source
    for match in _LIMIT_REGEX.finditer(source_text):
        variable = match.group(1)
        low_expr = match.group(2)
        expression = match.group(3)
        high_expr = match.group(4)

        low = _resolve_constant(low_expr, constants)
        high = _resolve_constant(high_expr, constants)

        info.limit_bounds.append(
            STLimitBound(
                variable=variable,
                expression=expression,
                low=low,
                high=high,
            )
        )

    # CASE FSM from source
    case_match = _CASE_REGEX.search(source_text)
    if case_match:
        state_var = case_match.group(1)
        case_body = case_match.group(2)
        state_ids = [
            int(m.group(1)) for m in _CASE_LABEL_REGEX.finditer(case_body)
        ]
        if state_ids:
            state_register = None
            for var in info.variables:
                if var.name == state_var:
                    state_register = var.resolved_register
                    break
            info.fsm = STFsmInfo(
                state_variable=state_var,
                state_register=state_register,
                state_ids=state_ids,
            )

    logger.info(
        "blark parser: %d variables, %d LIMIT bounds, FSM=%s",
        len(info.variables),
        len(info.limit_bounds),
        info.has_fsm,
    )
    return info


def parse_st_file(path: Path, register_offset: int = 0) -> STProgramInfo:
    """Parse an IEC 61131-3 Structured Text file.

    Attempts blark-based AST parsing first, falls back to regex extraction.

    Args:
        path: Path to the .st file.
        register_offset: Offset for AT address -> Modbus register mapping.

    Returns:
        Parsed program information.
    """
    source = path.read_text(encoding="utf-8", errors="replace")

    try:
        return _parse_with_blark(source, register_offset)
    except ImportError:
        logger.info("blark not installed, using regex parser")
        return _parse_with_regex(source, register_offset)
