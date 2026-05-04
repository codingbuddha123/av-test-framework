"""
Scenario Runner
Posts generated scenarios to the AV Decision Engine API.
Saves results.json consumed by the Java/Playwright validation layer.
"""

import json
import time
import requests
import argparse
from datetime import datetime
from pathlib import Path


API_URL     = "http://localhost:8080/api/v1/decision"
HEALTH_URL  = "http://localhost:8080/api/v1/health"


def check_server():
    try:
        r = requests.get(HEALTH_URL, timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def validate_result(scenario: dict, decision: dict) -> dict:
    """
    Safety validation rules — derived from MISRA/CERT/ISO 26262 requirements.
    Each rule maps to a compliance tag in the scenario.
    Returns a validation result with any violations found.
    """
    violations = []
    expected   = scenario["expected_behavior"]
    objects    = scenario["objects"]
    security   = scenario.get("security_context", {})

    # Rule 1: Critical proximity → STOP (ASIL-D, MISRA_C_2012_Rule_15_5)
    critical_obj = any(o["distance_m"] < 8 and o["lane_overlap"] for o in objects)
    if critical_obj and decision["action"] != "STOP":
        violations.append({
            "rule": "ASIL-D-STOP-001",
            "compliance": "ISO26262_ASIL_D",
            "description": f"Object within 8m with lane overlap — must STOP. Got: {decision['action']}",
            "severity": "CRITICAL"
        })

    # Rule 2: Response time (ISO 26262 timing requirement)
    if decision["response_time_ms"] > expected["max_response_time_ms"]:
        violations.append({
            "rule": "ISO26262-TIMING-001",
            "compliance": "ISO26262_ASIL_D",
            "description": f"Response {decision['response_time_ms']}ms exceeded limit {expected['max_response_time_ms']}ms",
            "severity": "HIGH"
        })

    # Rule 3: Security attack → must not CONTINUE (SAE J3061)
    under_attack = (
        security.get("spoofing_attack", "none") != "none" or
        security.get("signal_jamming", False) or
        security.get("replay_attack", False)
    )
    if under_attack and decision["action"] == "CONTINUE":
        violations.append({
            "rule": "SAE-J3061-SEC-001",
            "compliance": "SAE_J3061",
            "description": "Active security attack detected — must not CONTINUE",
            "severity": "CRITICAL"
        })

    # Rule 4: Fog + high speed → must brake (MISRA)
    vis   = scenario["environment"]["visibility_m"]
    speed = scenario["ego_vehicle"]["speed_mps"]
    if scenario["environment"]["weather"] == "fog" and vis < 25 and speed > 10:
        if decision["action"] not in ["STOP", "BRAKE"]:
            violations.append({
                "rule": "MISRA-VIS-001",
                "compliance": "MISRA_C_2012_Rule_15_5",
                "description": f"Fog with vis={vis}m, speed={speed}mps — must brake",
                "severity": "HIGH"
            })

    passed = len(violations) == 0
    return {
        "passed":     passed,
        "violations": violations
    }


def run(scenarios_file: str, output_file: str, max_scenarios: int = None):
    if not check_server():
        print("❌ AV Decision Engine not running. Start it with:")
        print("   python decision_engine_server.py")
        return

    print(f"✅ Server healthy. Loading scenarios from {scenarios_file}...")

    with open(scenarios_file) as f:
        data = json.load(f)

    scenarios = data["scenarios"]
    if max_scenarios:
        scenarios = scenarios[:max_scenarios]

    print(f"   Running {len(scenarios)} scenarios...\n")

    results     = []
    violations  = []
    passed      = 0
    failed      = 0

    for i, scenario in enumerate(scenarios):
        try:
            resp = requests.post(API_URL, json=scenario, timeout=5)
            decision = resp.json()
        except Exception as e:
            decision = {"error": str(e), "action": "ERROR"}

        validation = validate_result(scenario, decision)

        result = {
            "scenario_id":   scenario["id"],
            "name":          scenario["name"],
            "category":      scenario["category"],
            "severity":      scenario["severity"],
            "compliance_tags": scenario["compliance_tags"],
            "scenario":      scenario,
            "decision":      decision,
            "validation":    validation
        }

        results.append(result)

        if validation["passed"]:
            passed += 1
            status = "✅ PASS"
        else:
            failed += 1
            status = "❌ FAIL"
            violations.extend(validation["violations"])

        if i % 10 == 0 or not validation["passed"]:
            print(f"  [{i+1:3d}/{len(scenarios)}] {status} — {scenario['name'][:60]}")
            if not validation["passed"]:
                for v in validation["violations"]:
                    print(f"           ⚠️  {v['rule']}: {v['description']}")

    # Write results
    output = {
        "run_at":          datetime.now().isoformat(),
        "total":           len(results),
        "passed":          passed,
        "failed":          failed,
        "pass_rate":       f"{passed/len(results)*100:.1f}%",
        "total_violations": len(violations),
        "results":         results
    }

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*60}")
    print(f"  Total:     {len(results)}")
    print(f"  Passed:    {passed} ✅")
    print(f"  Failed:    {failed} ❌")
    print(f"  Pass rate: {passed/len(results)*100:.1f}%")
    print(f"  Violations:{len(violations)}")
    print(f"  Results → {output_file}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenarios", default="scenarios/scenarios.json")
    parser.add_argument("--output",    default="results/results.json")
    parser.add_argument("--max",       type=int, default=None)
    args = parser.parse_args()

    run(args.scenarios, args.output, args.max)
