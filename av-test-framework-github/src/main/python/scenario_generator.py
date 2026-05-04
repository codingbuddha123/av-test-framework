"""
AV Test Scenario Generator
Generates structured test scenarios with safety bias and security attack vectors.
Feeds scenarios.json consumed by the Java/Playwright test layer.
"""

import random
import json
import uuid
import argparse
from datetime import datetime


# ── Weighted distributions (safety-biased, not uniform) ──────────────────────

WEATHER_WEIGHTS = {
    "clear": 0.20,   # underweight clear — less interesting
    "fog":   0.30,   # overweight adversarial conditions
    "rain":  0.25,
    "snow":  0.15,
    "night": 0.10
}

SEVERITY_WEIGHTS = {
    "critical": 0.40,  # bias toward cases that matter
    "high":     0.35,
    "medium":   0.15,
    "low":      0.10
}

CATEGORIES = ["collision", "security", "sensor", "braking", "lane"]

COMPLIANCE_MAP = {
    "collision": ["MISRA_C_2012_Rule_15_5", "CERT_EXP34_C", "ISO26262_ASIL_D"],
    "security":  ["CERT_INT30_C", "CERT_STR31_C", "MISRA_C_2012_Rule_21_3", "SAE_J3061"],
    "sensor":    ["MISRA_C_2012_Rule_14_2", "CERT_FLP32_C", "ISO26262_ASIL_B"],
    "braking":   ["MISRA_C_2012_Rule_15_3", "ISO26262_ASIL_D", "CERT_INT32_C"],
    "lane":      ["MISRA_C_2012_Rule_13_5", "CERT_EXP36_C", "ISO26262_ASIL_C"]
}


def weighted_choice(weights: dict):
    items = list(weights.keys())
    probs = list(weights.values())
    return random.choices(items, weights=probs, k=1)[0]


def generate_ego_vehicle(severity: str) -> dict:
    """Higher severity = higher speed, more aggressive state."""
    if severity == "critical":
        speed = random.uniform(18, 30)       # highway+ speed
        accel = random.uniform(-8, -3)       # hard braking range
    elif severity == "high":
        speed = random.uniform(12, 20)
        accel = random.uniform(-6, -1)
    else:
        speed = random.uniform(0, 15)
        accel = random.uniform(-3, 2)

    return {
        "speed_mps": round(speed, 2),
        "acceleration_mps2": round(accel, 2),
        "heading_deg": round(random.uniform(0, 360), 1),
        "lane_position": random.choice(["left", "center", "right"])
    }


def generate_environment(weather: str) -> dict:
    """Visibility degrades with adversarial weather."""
    vis_ranges = {
        "clear": (80, 200),
        "fog":   (5, 30),    # dangerous low visibility
        "rain":  (20, 80),
        "snow":  (10, 50),
        "night": (15, 60)
    }
    low, high = vis_ranges[weather]
    return {
        "weather": weather,
        "visibility_m": round(random.uniform(low, high), 1),
        "road_condition": random.choice(["dry", "wet", "icy"]) if weather in ["rain", "snow"] else "dry",
        "lighting": "night" if weather == "night" else random.choice(["day", "dusk"])
    }


def generate_objects(category: str, severity: str) -> list:
    """Generate traffic objects appropriate to category and severity."""
    objects = []
    count = 1 if severity in ["low", "medium"] else random.randint(1, 3)

    for i in range(count):
        if category == "collision":
            obj_type = random.choice(["pedestrian", "vehicle", "cyclist"])
            distance = random.uniform(2, 12) if severity == "critical" else random.uniform(5, 40)
            overlap = True if severity in ["critical", "high"] else random.choice([True, False])
        elif category == "security":
            obj_type = "vehicle"
            distance = random.uniform(10, 60)
            overlap = random.choice([True, False])
        else:
            obj_type = random.choice(["vehicle", "obstacle"])
            distance = random.uniform(5, 80)
            overlap = random.choice([True, False])

        objects.append({
            "id": f"obj_{i+1}",
            "type": obj_type,
            "distance_m": round(distance, 2),
            "relative_speed_mps": round(random.uniform(-15, 15), 2),
            "lane_overlap": overlap,
            "trajectory": random.choice(["crossing", "approaching", "stationary", "following"])
        })

    return objects


def generate_security_context(category: str) -> dict:
    """Security scenarios inject attacks; others are clean."""
    if category == "security":
        attack_type = random.choice(["gps", "lidar", "camera", "none"])
        return {
            "spoofing_attack": attack_type,
            "signal_jamming": random.choice([True, False]),
            "replay_attack": random.choice([True, False]),
            "data_injection": random.choice([True, False])
        }
    return {
        "spoofing_attack": "none",
        "signal_jamming": False,
        "replay_attack": False,
        "data_injection": False
    }


def derive_expected_behavior(scenario: dict) -> dict:
    """
    Rule-based expected behavior derivation.
    This is the validation contract — what the AV MUST do.
    MISRA/CERT compliance requires deterministic safety decisions.
    """
    objects   = scenario["objects"]
    speed     = scenario["ego_vehicle"]["speed_mps"]
    weather   = scenario["environment"]["weather"]
    vis       = scenario["environment"]["visibility_m"]
    security  = scenario["security_context"]
    severity  = scenario["severity"]

    # Critical safety rules (ASIL-D level — must never fail)
    critical_object = any(
        o["distance_m"] < 8 and o["lane_overlap"] for o in objects
    )
    under_attack = (
        security["spoofing_attack"] != "none" or
        security["signal_jamming"] or
        security["replay_attack"]
    )
    low_vis_high_speed = vis < 25 and speed > 15

    if critical_object or (under_attack and severity == "critical"):
        action = "STOP"
        response_ms = 150
        decel = 8.0
        alert = "critical"
    elif low_vis_high_speed or under_attack:
        action = "BRAKE"
        response_ms = 300
        decel = 4.0
        alert = "warning"
    elif any(o["distance_m"] < 20 and o["lane_overlap"] for o in objects):
        action = "BRAKE"
        response_ms = 400
        decel = 2.5
        alert = "warning"
    elif security["data_injection"]:
        action = "ALERT"
        response_ms = 500
        decel = 0
        alert = "warning"
    else:
        action = "CONTINUE"
        response_ms = 1000
        decel = 0
        alert = "none"

    return {
        "action": action,
        "max_response_time_ms": response_ms,
        "min_deceleration_mps2": decel,
        "alert_level": alert
    }


def generate_scenario(category: str = None, severity: str = None) -> dict:
    """Generate a single complete test scenario."""
    category = category or random.choice(CATEGORIES)
    severity = severity or weighted_choice(SEVERITY_WEIGHTS)
    weather  = weighted_choice(WEATHER_WEIGHTS)

    scenario = {
        "id": str(uuid.uuid4())[:8],
        "name": f"{category}_{severity}_{weather}_{datetime.now().strftime('%H%M%S')}",
        "category": category,
        "severity": severity,
        "compliance_tags": COMPLIANCE_MAP[category],
        "ego_vehicle": generate_ego_vehicle(severity),
        "environment": generate_environment(weather),
        "traffic_signals": {
            "state": random.choice(["RED", "GREEN", "YELLOW", "NONE"]),
            "distance_m": round(random.uniform(5, 150), 1),
            "time_to_change_s": round(random.uniform(0, 30), 1)
        },
        "objects": generate_objects(category, severity),
        "security_context": generate_security_context(category)
    }

    # Derive expected behavior from the scenario parameters
    scenario["expected_behavior"] = derive_expected_behavior(scenario)
    return scenario


def generate_batch(
    total: int = 100,
    output_file: str = "scenarios/scenarios.json",
    force_critical: int = 20
) -> None:
    """
    Generate a balanced batch.
    force_critical: number of guaranteed critical security scenarios.
    """
    scenarios = []

    # Guarantee critical security scenarios (most important for NVIDIA AV)
    for _ in range(force_critical):
        scenarios.append(generate_scenario(category="security", severity="critical"))

    # Fill rest with biased random distribution
    for _ in range(total - force_critical):
        scenarios.append(generate_scenario())

    random.shuffle(scenarios)

    with open(output_file, "w") as f:
        json.dump({"generated_at": datetime.now().isoformat(),
                   "total": len(scenarios),
                   "scenarios": scenarios}, f, indent=2)

    # Summary
    categories = {}
    severities = {}
    for s in scenarios:
        categories[s["category"]] = categories.get(s["category"], 0) + 1
        severities[s["severity"]] = severities.get(s["severity"], 0) + 1

    print(f"\n✅ Generated {len(scenarios)} scenarios → {output_file}")
    print(f"   Categories: {categories}")
    print(f"   Severities: {severities}")
    actions = {}
    for s in scenarios:
        a = s["expected_behavior"]["action"]
        actions[a] = actions.get(a, 0) + 1
    print(f"   Expected actions: {actions}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AV Test Scenario Generator")
    parser.add_argument("--total", type=int, default=100, help="Total scenarios to generate")
    parser.add_argument("--critical", type=int, default=20, help="Forced critical security scenarios")
    parser.add_argument("--output", type=str, default="scenarios/scenarios.json")
    args = parser.parse_args()

    generate_batch(total=args.total, output_file=args.output, force_critical=args.critical)
