# ICS Register Value Summarization: Analysis & Design

This document summarizes the current implementation for Modbus register tracking, its limitations, and potential improvements for APT detection use cases.

---

## 1. Current Implementation

### 1.1 Overview

The system augments ICS security telemetry (Sysmon/ETW logs) with PCAP network traffic to create provenance graphs in Neo4j. For Modbus traffic specifically, it extracts register-level details to provide visibility into PLC communications.

### 1.2 Transaction Matching

Modbus uses a request/response pattern where:
- **Requests** contain register addresses but no values
- **Responses** contain values but no addresses

The system pairs them using a transaction key:

```
key = (client_ip, client_port, server_ip, unit_id, transaction_id)
```

**Flow:**
1. On REQUEST: Store pending request with register addresses
2. On RESPONSE: Pop matching request, zip addresses with values
3. Result: Know that register 40001 = 100, register 40002 = 200, etc.

**Implementation:** `enhancer.py:_collect_modbus_registers()` (lines 1785-1915)

### 1.3 Per-Register Statistics

For each `(register_address, unit_id)` pair, the `_RegisterAccumulator` class tracks:

| Statistic | Description |
|-----------|-------------|
| `read_count` / `write_count` | Operation counters |
| `min_value` / `max_value` | Observed range |
| `mean_value` | Running average (Welford's algorithm) |
| `distinct_values` | Cardinality estimate (HyperLogLog-style bitmask) |
| `state_changes` | Transition count (for coils) |
| `top_values` | Frequency table (top 4 values) |
| `value_timeline` | SDT-compressed timeline (~100 points max) |

**Implementation:** `enhancer.py:_RegisterAccumulator` (lines 306-451)

### 1.4 SDT (Swinging Door Trending) Compression

The timeline compression algorithm:

1. Maintains an "aperture" defined by upper/lower slopes from last stored point
2. New point inside aperture → update slopes, keep as pending
3. New point outside aperture → store pending point, store new point, reset slopes
4. If points exceed limit (100), double tolerance and recompress

**Output format:** `"@<base_timestamp>|<delta>:<value>,<delta>:<value>,..."`

**Implementation:** `enhancer.py:_SDTCompressor` (lines 194-294)

### 1.5 Neo4j Output

```cypher
MERGE (r:Register {guid: $guid})
SET r += {
  address: 40001,
  unitId: 1,
  readCount: 15000,
  writeCount: 0,
  minValue: 95,
  maxValue: 210,
  meanValue: 150.3,
  stateChanges: 0,
  topValues: "150:8000,151:4000,149:2000,152:1000",
  valueTimeline: "@1703847123.456|0.00:150,12.50:160,45.00:95,..."
}
```

---

## 2. Limitations of Current Approach

### 2.1 SDT Fails for Binary Signals

SDT assumes analog signals with gradual trends. For binary (0/1) values:

| Tolerance | Behavior |
|-----------|----------|
| `≥ 1.0` | Entire range within tolerance → almost nothing stored, transitions lost |
| `< 1.0` | Every transition triggers storage → no compression benefit |

**Example:** A pump cycling ON/OFF every 30 seconds would either:
- Lose all transition information (tolerance too high)
- Store every single sample (tolerance too low)

### 2.2 No Signal Type Awareness

The current implementation applies the same summarization strategy to all registers regardless of whether they represent:
- Binary states (coils)
- Duty-cycle signals (cycling equipment)
- Slow-changing analog (temperature)
- Fast-changing analog (flow rate)
- Setpoints (rarely changing configuration)
- Counters (monotonic accumulators)

### 2.3 Limited Anomaly Detection Support

The current statistics are descriptive but not designed for anomaly detection:

| Current Metric | Anomaly Detection Gap |
|----------------|----------------------|
| `min/max/mean` | No baseline to compare against |
| `state_changes` | No expected rate to detect stuck/chattering |
| `value_timeline` | Compressed for storage, not queryable for patterns |
| No entropy | Can't detect distribution anomalies |
| No change rate | Can't detect frequency anomalies |

### 2.4 No Cross-Register Correlation

Physical processes have invariants:
- If `PUMP_CMD=1`, then `FLOW_SENSOR > 0` within 5 seconds
- `INLET_FLOW ≈ OUTLET_FLOW` (mass balance)
- `TEMP` can't change > 10°C/second

An attacker manipulating one register but not its correlated partners would not be detected by single-register summaries alone.

---

## 3. Signal Type Analysis

### 3.1 Signal Types in ICS/Modbus

| Type | Example | Characteristics |
|------|---------|-----------------|
| **Binary - State** | Pump running, valve open, alarm active | ON or OFF, changes on discrete events |
| **Binary - Duty Cycle** | Cycling compressor, batch step, heartbeat | Toggles regularly, period/ratio defines normal |
| **Discrete - Enumerated** | Valve position (OPEN/CLOSED/TRANSIT), mode (AUTO/MANUAL) | Small fixed set of valid states |
| **Analog - Slow** | Tank level, temperature, vessel pressure | Gradual change, physical inertia |
| **Analog - Noisy** | Flow rate, vibration, electrical current | High variance, rapid fluctuation |
| **Setpoint/Config** | Temperature setpoint, PID tuning, thresholds | Rarely changes, operator-initiated |
| **Counter/Accumulator** | Production count, runtime hours, error count | Monotonic increase, possible rollover |

### 3.2 What Constitutes "Anomalous" Per Type

| Signal Type | Normal | Anomalous |
|-------------|--------|-----------|
| **Binary - State** | Transitions on process events | Stuck when should change, unexpected state |
| **Binary - Duty Cycle** | Consistent period and ratio | Period drift, duty cycle shift, missing cycles |
| **Discrete - Enum** | Valid states, legal transitions | Invalid value, impossible transition sequence |
| **Analog - Slow** | Within range, gradual change | Out of range, impossible rate of change, frozen |
| **Analog - Noisy** | Consistent mean/variance | Mean shift, variance collapse (fake data), spikes |
| **Setpoint/Config** | Stable except maintenance | Unauthorized change, change during production |
| **Counter** | Monotonic at expected rate | Decrease (rollback), jump, rate anomaly |

---

## 4. Constraints & Design Considerations

### 4.1 Storage Constraints

**Requirement:** Summary must be bounded, not grow with sample count.

**Current:** SDT targets ~100 points max, plus fixed statistics. Roughly O(500-1000) bytes per register.

**Consideration:** What's the actual budget? This determines how much event history we can retain.

### 4.2 Detection vs. Storage Tradeoff

```
                    High
                      │
   Detection         │    ● Store everything
   Capability        │       (not feasible)
                      │
                      │         ● Store events + stats
                      │            (bounded, good detection)
                      │
                      │              ● Store only aggregate stats
                      │                 (very compact, limited detection)
                      │
                    Low └─────────────────────────────────────────
                              Low                            High
                                    Storage Efficiency
```

### 4.3 What's Detectable from Summaries

**CAN detect:**
- Stuck/frozen sensor (zero variance, no changes)
- Range violations (min/max outside bounds)
- Distribution shift (mean, variance, entropy deviation)
- Rate anomalies (change frequency too high/low)
- Duty cycle anomalies (period or ratio deviation)
- Invalid states (value not in allowed set)
- Counter rollback (max decreased)

**CANNOT detect well:**
- Precise timing of specific events (summarized away)
- Subtle within-range manipulation (looks normal in aggregate)
- Cross-register inconsistencies (requires correlation, not single-register summary)
- Short-lived anomalies (averaged out)

### 4.4 Open Questions

1. **Storage budget:** What's the target bytes per register? 100? 500? 1KB?

2. **Baseline assumption:** Is there a learning phase to establish "normal," or must detection work from first packet?

3. **Cross-register scope:** Is correlation analysis part of this layer, or handled separately in graph queries?

4. **Event granularity:** Need to reconstruct "what happened at time T" or just "was there an anomaly"?

5. **Signal type configuration:** Auto-detect from observed data, or require asset metadata (e.g., "register 40001 is temperature")?

---

## 5. Proposed Approach: Adaptive Signal Profiling

### 5.1 Core Idea

1. **Auto-detect signal type** from observed value characteristics
2. **Store universal metrics** that apply to all types
3. **Store change events** (generalizes across all signal types)
4. **Compute anomaly-relevant features** not just descriptive stats

### 5.2 Signal Type Detection

```python
def classify_signal(values: List[int]) -> str:
    distinct = len(set(values))

    if distinct == 2:
        return "binary"
    elif distinct <= 10:
        return "discrete"
    else:
        # Could further distinguish slow vs noisy analog
        # based on variance or autocorrelation
        return "analog"
```

### 5.3 Universal Metrics (All Signal Types)

| Metric | Purpose |
|--------|---------|
| `sampleCount` | Data volume |
| `firstSeenAt` / `lastSeenAt` | Temporal bounds |
| `minValue` / `maxValue` | Range |
| `meanValue` / `variance` | Distribution shape |
| `distinctValues` | Cardinality |
| `entropy` | Information content (key for anomaly detection) |
| `changeCount` | Number of significant changes |
| `changeRate` | Changes per unit time |
| `lastChangeAt` | Staleness detection |

### 5.4 Change Events (Universal Concept)

A "change" means different things per signal type:

| Signal Type | What Triggers a Change Event |
|-------------|------------------------------|
| Binary | Any transition (0→1 or 1→0) |
| Discrete | State change (A→B) |
| Analog | Value crossed threshold, or delta > X |

Store bounded list of recent events:
```
recentEvents: "0.0:0→1,30.0:1→0,45.0:0→1,..."
```

### 5.5 Signal-Type Specific Metrics

**Binary:**
- `dutyCycle` - fraction of time in state 1
- `avgOnDuration` / `avgOffDuration`
- `transitionCount`

**Discrete:**
- `stateDistribution` - time fraction per state
- `transitionMatrix` - observed state transitions (optional)

**Analog:**
- `rateOfChangeMean` / `rateOfChangeMax`
- `thresholdCrossings`

**Counter:**
- `totalDelta` - cumulative change
- `rollbackCount` - decreases observed
- `ratePerSecond`

### 5.6 Anomaly-Oriented Features

| Feature | What It Detects |
|---------|-----------------|
| `entropy` | Stuck (≈0), manipulation (abnormal distribution) |
| `changeRate` | Stuck (too low), chattering (too high) |
| `variance` | Frozen (≈0), noisy sensor failure (spike) |
| `dominantRatio` | Unbalanced behavior |
| `stuckScore` | Explicit flag: expected changes that didn't happen |

### 5.7 Example Output

```cypher
MERGE (r:Register {guid: $guid})
SET r += {
  // Identity
  address: 40001,
  unitId: 1,
  signalType: "binary",  // auto-detected

  // Universal
  sampleCount: 15000,
  firstSeenAt: 1703847000.0,
  lastSeenAt: 1703850600.0,

  // Distribution
  minValue: 0,
  maxValue: 1,
  distinctValues: 2,
  entropy: 0.92,

  // Change behavior
  changeCount: 847,
  changeRate: 0.14,
  lastChangeAt: 1703850598.5,

  // Binary-specific
  dutyCycle: 0.58,
  avgOnDuration: 35.2,
  avgOffDuration: 25.8,

  // Bounded event log
  recentEvents: "3598.5:0→1,3628.5:1→0,3654.2:0→1"
}
```

---

## 6. Detection Capabilities

### 6.1 Graph Queries Enabled

```cypher
// Stuck sensors (no changes when should have)
MATCH (r:Register)
WHERE r.changeCount = 0 AND r.sampleCount > 1000
RETURN r.address, r.signalType

// Abnormal entropy (possible replay/fake data)
MATCH (r:Register)
WHERE r.signalType = "binary" AND r.entropy < 0.1
RETURN r.address, r.entropy

// Duty cycle anomaly
MATCH (r:Register)
WHERE r.signalType = "binary"
  AND abs(r.dutyCycle - 0.5) > 0.3  // Expect ~50% duty
RETURN r.address, r.dutyCycle

// Range violations
MATCH (r:Register)
WHERE r.maxValue > 1000 OR r.minValue < 0
RETURN r.address, r.minValue, r.maxValue

// Counter rollback (possible tampering)
MATCH (r:Register)
WHERE r.signalType = "counter" AND r.rollbackCount > 0
RETURN r.address, r.rollbackCount
```

### 6.2 What Remains Out of Scope

1. **Cross-register correlation** - Detecting "pump ON but flow = 0" requires joining multiple registers. This could be:
   - Pre-computed during augmentation (store correlation scores)
   - Computed at query time in Neo4j
   - Handled by a separate analysis layer

2. **Baseline establishment** - Current design computes statistics but doesn't compare to "expected normal." Options:
   - Store baseline separately (from training data)
   - Use asset metadata to define expected ranges
   - Compute deviation scores at query time

3. **Temporal pattern detection** - Detecting "this always happens at 3am" requires time-series analysis beyond simple summaries.

---

## 7. Possible Next Steps

### 7.1 Immediate (Improve Current Implementation)

1. **Add signal type detection** to `_RegisterAccumulator`
   - Classify based on observed cardinality
   - Store as property on Register node

2. **Add entropy calculation**
   - Use value frequency distribution
   - Strong signal for anomaly detection

3. **Replace SDT with transition encoding for binary signals**
   - If `distinctValues == 2`, use event-based storage instead of SDT
   - Store transitions, duty cycle, avg durations

4. **Add change rate tracking**
   - `changeCount / duration`
   - Key metric for stuck/chattering detection

### 7.2 Medium-Term (Enhanced Detection)

5. **Add anomaly score rollup**
   - Pre-compute `stuckScore`, `rangeViolationCount`, `entropyAnomaly`
   - Enables simple graph queries for detection

6. **Implement cross-register correlation**
   - Define expected relationships in asset metadata
   - Compute and store correlation violations

7. **Add bounded anomaly event log**
   - Store last N anomalous observations with timestamps
   - Enables "what happened" queries

### 7.3 Long-Term (Architecture)

8. **Separate raw storage from graph**
   - Graph contains summaries and anomaly flags
   - Raw events stored in time-series DB for drill-down
   - Enables detailed forensics without bloating graph

9. **Baseline/profile system**
   - Learn "normal" from training period
   - Store expected ranges, change rates, correlations
   - Compare live traffic against baseline

---

## 8. Summary

| Aspect | Current State | Gap | Proposed |
|--------|---------------|-----|----------|
| **Transaction matching** | ✅ Implemented | - | Keep as-is |
| **Basic statistics** | ✅ min/max/mean | No anomaly focus | Add entropy, change rate |
| **Timeline compression** | ⚠️ SDT only | Fails for binary | Adaptive per signal type |
| **Signal type handling** | ❌ One-size-fits-all | - | Auto-detect and adapt |
| **Anomaly detection** | ❌ Not designed for it | - | Add anomaly-oriented metrics |
| **Cross-register** | ❌ Not implemented | - | Future: correlation analysis |

The core insight is that **summarization strategy should adapt to signal type**, and **metrics should be chosen for anomaly detection value**, not just descriptive completeness.
