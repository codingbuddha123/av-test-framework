# CERT C Coding Standard — AV Security Compliance Rules

## Overview
CERT C provides secure coding rules to eliminate undefined behaviors and
security vulnerabilities in C/C++ code. Critical for AV cybersecurity (SAE J3061).

---

## Rules Validated in This Framework

### EXP34-C — Do Not Dereference Null Pointers
**Severity:** High  
**Applies to:** Sensor data processing, object detection output

**AV Context:** If sensor data returns null (e.g., due to spoofing), the decision
engine must handle it safely — not dereference and crash.

**Validation Check:**
```
SCENARIO: security scenarios with spoofing_attack != "none"
EXPECTED: Decision returned (even if degraded) — engine does not crash
VIOLATION: API returns 500 or no response within timeout
```
**Framework Rule ID:** `CERT_EXP34_C`

---

### INT30-C — Ensure Unsigned Integer Operations Do Not Wrap
**Severity:** High  
**Applies to:** Timestamp validation in replay attack detection

**AV Context:** Replay attacks inject old sensor data. Timestamp comparison
using unsigned integers can wrap, allowing old data to appear valid.

**Validation Check:**
```
SCENARIO: security scenarios with replay_attack: true
EXPECTED: Engine rejects old data — action != CONTINUE
VIOLATION: replay_attack=true but CONTINUE returned (timestamp wraparound)
```
**Framework Rule ID:** `CERT_INT30_C`

---

### INT32-C — Ensure Operations on Signed Integers Do Not Overflow
**Severity:** Medium  
**Applies to:** Deceleration calculation, distance arithmetic

**AV Context:** Integer overflow in braking distance calculation could cause
underestimation of required stopping distance.

**Validation Check:**
```
SCENARIO: braking scenarios at maximum speed (speed_mps: 25–30)
EXPECTED: Deceleration value positive and within physical limits (0–8 m/s²)
VIOLATION: deceleration_mps2 < 0 or > 8 (overflow artifact)
```
**Framework Rule ID:** `CERT_INT32_C`

---

### STR31-C — String Length Validation
**Severity:** Medium  
**Applies to:** API input parsing, JSON field validation

**AV Context:** Malformed or oversized inputs via the API could cause buffer
overflows in the C++ decision engine.

**Validation Check:**
```
SCENARIO: All scenarios (API input validation)
EXPECTED: API returns structured JSON response
VIOLATION: API crashes or returns 500 on large/malformed input
```
**Framework Rule ID:** `CERT_STR31_C`

---

### FLP32-C — Prevent or Detect Domain and Range Errors in Math Functions
**Severity:** Medium  
**Applies to:** Visibility calculations, trajectory prediction

**AV Context:** Math operations on sensor inputs (e.g., `sqrt` of negative value
from corrupted distance sensor) must be validated.

**Validation Check:**
```
SCENARIO: sensor scenarios with extreme visibility values (< 1m or > 500m)
EXPECTED: Engine clamps to safe range, decision still valid
VIOLATION: NaN or Infinity in response fields
```
**Framework Rule ID:** `CERT_FLP32_C`

---

## SAE J3061 — Cybersecurity Guidebook for Cyber-Physical Vehicle Systems

### Threat: Sensor Spoofing
**Rule:** Any detected spoofing must trigger protective action
```
SCENARIO: spoofing_attack != "none"
EXPECTED: action in [STOP, BRAKE, ALERT]
VIOLATION: action == CONTINUE
```

### Threat: Signal Jamming  
**Rule:** Loss of sensor signal must trigger fail-safe mode
```
SCENARIO: signal_jamming == true
EXPECTED: alert_level in [warning, critical]
VIOLATION: alert_level == none
```

### Threat: Replay Attack
**Rule:** Replayed sensor data must be detected and rejected
```
SCENARIO: replay_attack == true
EXPECTED: action != CONTINUE
VIOLATION: System accepts replayed data as valid
```

---

## Compliance Report Format

The framework generates `reports/compliance_report.json` after each run:

```json
{
  "rule": "CERT_INT30_C",
  "description": "Unsigned integer wrap in replay detection",
  "scenarios_tested": 20,
  "violations": 3,
  "violation_rate": "15%",
  "verdict": "FAIL",
  "severity": "HIGH"
}
```

---

## References
- CERT C Coding Standard: https://wiki.sei.cmu.edu/confluence/display/c/
- SAE J3061:2016 — Cybersecurity Guidebook for Cyber-Physical Vehicle Systems
- ISO/SAE 21434:2021 — Road vehicles cybersecurity engineering
