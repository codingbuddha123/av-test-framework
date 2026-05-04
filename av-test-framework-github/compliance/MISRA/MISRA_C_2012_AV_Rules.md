# MISRA C:2012 — Compliance Rules for Autonomous Vehicle Systems

## Overview
MISRA C:2012 provides guidelines for the use of C in safety-critical embedded systems.
These rules are validated automatically by the AV Test Framework compliance checker.

---

## Rules Validated in This Framework

### Rule 15.5 — Single Exit Point
**Category:** Required  
**Applies to:** Decision engine functions  
**Description:** A function should have a single point of exit at the end.

**AV Context:** The `process_decision()` function must have a single return point.
Multiple early returns in safety-critical code create untestable paths.

**Validation Check:**
```
SCENARIO: Any scenario that reaches decision engine
EXPECTED: Single decision returned per scenario
VIOLATION: Multiple conflicting actions returned
```

**Framework Rule ID:** `MISRA_RULE_15_5`

---

### Rule 14.2 — For Loop Constraint
**Category:** Required  
**Applies to:** Sensor data iteration loops  
**Description:** A for-loop shall be well-formed — counter must not be modified in body.

**AV Context:** Object detection loops iterating over sensor returns must be deterministic.

**Validation Check:**
```
SCENARIO: sensor category scenarios with multiple objects
EXPECTED: All objects processed, none skipped
VIOLATION: Object count in result != object count in scenario
```

**Framework Rule ID:** `MISRA_RULE_14_2`

---

### Rule 13.5 — Side Effects in Logical Operators
**Category:** Required  
**Applies to:** Safety condition evaluation  
**Description:** The right-hand operand of a logical `&&` or `||` operator shall not contain persistent side effects.

**AV Context:** Safety conditions like `(distance < STOP_DIST && lane_overlap)` must not trigger side effects.

**Validation Check:**
```
SCENARIO: collision scenarios requiring compound condition evaluation
EXPECTED: Decision consistent regardless of evaluation order
VIOLATION: Different results on repeated calls with same input
```

**Framework Rule ID:** `MISRA_RULE_13_5`

---

### Rule 21.3 — Memory Allocation
**Category:** Required  
**Applies to:** Real-time decision engine  
**Description:** The memory allocation and deallocation functions of `<stdlib.h>` shall not be used.

**AV Context:** Dynamic memory allocation in real-time safety paths is prohibited.
Decision engine must use static allocation only.

**Validation Check:**
```
SCENARIO: High-frequency scenario execution (100+ scenarios/sec)
EXPECTED: Response time stable, no GC pauses
VIOLATION: Response time spikes indicating dynamic allocation
```

**Framework Rule ID:** `MISRA_RULE_21_3`

---

## Compliance Severity Levels

| Level | Description | AV Impact |
|-------|-------------|-----------|
| **Mandatory** | Shall always be followed | Safety-critical — ASIL-D |
| **Required** | Shall be followed with documented deviation | Safety-relevant — ASIL-B/C |
| **Advisory** | Should be followed where practical | Quality-relevant |

---

## Test Framework Mapping

Each scenario carries `compliance_tags` that map to rules above:

```json
"compliance_tags": [
  "MISRA_C_2012_Rule_15_5",
  "MISRA_C_2012_Rule_14_2"
]
```

The `ComplianceValidator.java` class reads these tags and applies the
appropriate validation logic during test execution.

---

## References
- MISRA C:2012 — Guidelines for the use of the C language in critical systems
- ISO 26262:2018 — Road vehicles functional safety
- AUTOSAR Coding Guidelines (subset of MISRA)
