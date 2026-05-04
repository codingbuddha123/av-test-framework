"""
Mock AV Decision Engine API
Simulates the C++ autonomous vehicle decision system over HTTP.
Playwright and REST Assured tests hit this endpoint.

In a real NVIDIA setup this would be the actual AV stack REST API.
Run: python decision_engine_server.py
"""

import json
import time
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse


class DecisionEngine:
    """
    Simulates the autonomous vehicle decision logic.
    Intentionally has bugs in some edge cases — your tests will find them.
    """

    STOP_DISTANCE_M    = 8.0    # MISRA: must be a named constant, not magic number
    BRAKE_DISTANCE_M   = 20.0
    MAX_SAFE_SPEED_FOG = 10.0   # mps in fog < 25m visibility
    ATTACK_RESPONSE_MS = 150    # ISO 26262 ASIL-D response requirement

    def process(self, scenario: dict) -> dict:
        start_time = time.time()

        objects   = scenario.get("objects", [])
        speed     = scenario["ego_vehicle"]["speed_mps"]
        weather   = scenario["environment"]["weather"]
        vis       = scenario["environment"]["visibility_m"]
        security  = scenario.get("security_context", {})

        action = "CONTINUE"
        alert  = "none"
        decel  = 0.0

        # ── Security checks (highest priority) ──────────────────
        spoofing = security.get("spoofing_attack", "none")
        jamming  = security.get("signal_jamming", False)
        replay   = security.get("replay_attack", False)

        if spoofing != "none" and jamming:
            action = "STOP"
            alert  = "critical"
            decel  = 8.0
        elif spoofing != "none" or replay:
            # BUG: should STOP, currently only BRAKEs — your test will catch this
            action = "BRAKE"
            alert  = "warning"
            decel  = 4.0
        elif security.get("data_injection", False):
            action = "ALERT"
            alert  = "warning"

        # ── Collision checks ─────────────────────────────────────
        if action == "CONTINUE":
            for obj in objects:
                dist    = obj["distance_m"]
                overlap = obj["lane_overlap"]

                if dist < self.STOP_DISTANCE_M and overlap:
                    action = "STOP"
                    alert  = "critical"
                    decel  = 8.0
                    break
                elif dist < self.BRAKE_DISTANCE_M and overlap:
                    action = "BRAKE"
                    alert  = "warning"
                    decel  = max(decel, 2.5)

        # ── Environmental checks ─────────────────────────────────
        if action == "CONTINUE":
            if weather == "fog" and vis < 25 and speed > self.MAX_SAFE_SPEED_FOG:
                action = "BRAKE"
                alert  = "warning"
                decel  = 3.0

        # ── Simulate processing time (with occasional latency spikes) ──
        base_latency = random.uniform(0.05, 0.12)
        if random.random() < 0.05:          # 5% chance of slow response
            base_latency += random.uniform(0.2, 0.5)
        time.sleep(base_latency)

        elapsed_ms = int((time.time() - start_time) * 1000)

        return {
            "action":             action,
            "alert_level":        alert,
            "deceleration_mps2":  round(decel, 2),
            "response_time_ms":   elapsed_ms,
            "engine_version":     "mock-1.0.0",
            "confidence":         round(random.uniform(0.75, 0.99), 3)
        }


class AVRequestHandler(BaseHTTPRequestHandler):
    engine = DecisionEngine()

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/v1/decision":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)

            try:
                scenario = json.loads(body)
                result   = self.engine.process(scenario)
                self._respond(200, result)
            except Exception as e:
                self._respond(400, {"error": str(e)})

        elif path == "/api/v1/health":
            self._respond(200, {"status": "ok", "engine": "mock-1.0.0"})

        else:
            self._respond(404, {"error": "endpoint not found"})

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/v1/health":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not found"})

    def _respond(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        # Suppress default Apache-style logging
        pass


if __name__ == "__main__":
    port = 8080
    server = HTTPServer(("localhost", port), AVRequestHandler)
    print(f"🚗 AV Decision Engine mock running on http://localhost:{port}")
    print(f"   POST /api/v1/decision  → process scenario")
    print(f"   GET  /api/v1/health    → health check")
    print(f"\n   Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n⛔ Server stopped")
