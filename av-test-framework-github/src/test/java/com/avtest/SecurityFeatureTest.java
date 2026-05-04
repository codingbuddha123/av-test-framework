package com.avtest;

import com.avtest.api.ResultsLoader;
import com.avtest.api.ScenarioResult;
import com.microsoft.playwright.*;
import org.junit.jupiter.api.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AV Security Feature Tests
 * Tests the vehicle's response to active cybersecurity attacks.
 * Compliance: SAE J3061, CERT_INT30_C, MISRA_C_2012_Rule_21_3
 *
 * Uses Playwright for API testing (JSON request/response validation).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("AV Security — Attack Response Validation")
public class SecurityFeatureTest {

    private static final String API_URL = "http://localhost:8080/api/v1/decision";

    private static Playwright playwright;
    private static APIRequestContext apiContext;
    private static List<ScenarioResult> securityResults;

    @BeforeAll
    static void setUp() throws Exception {
        // Playwright API context
        playwright = Playwright.create();
        apiContext = playwright.request().newContext(
            new APIRequest.NewContextOptions()
                .setBaseURL("http://localhost:8080")
                .setExtraHTTPHeaders(Map.of("Content-Type", "application/json"))
        );

        securityResults = ResultsLoader.loadByCategory("security");
        System.out.printf("\n🔒 Loaded %d security scenarios%n", securityResults.size());
    }

    @AfterAll
    static void tearDown() {
        if (apiContext != null) apiContext.dispose();
        if (playwright   != null) playwright.close();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SAE J3061: Active attack → must never CONTINUE
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(1)
    @DisplayName("[SAE-J3061] Active security attack → must not CONTINUE")
    void underAttack_mustNotContinue() {
        List<ScenarioResult> attacked = securityResults.stream()
            .filter(ScenarioResult::isUnderSecurityAttack)
            .toList();

        assertFalse(attacked.isEmpty(), "No active attack scenarios found");

        List<ScenarioResult> violations = attacked.stream()
            .filter(r -> "CONTINUE".equals(r.decision.action))
            .toList();

        if (!violations.isEmpty()) {
            StringBuilder msg = new StringBuilder(
                String.format("SAE-J3061 VIOLATION: %d attack scenarios returned CONTINUE:%n",
                    violations.size()));
            violations.forEach(v -> msg.append(String.format("  • %s%n", v.name)));
            fail(msg.toString());
        }

        System.out.printf("  ✅ All %d attack scenarios responded with protective action%n",
            attacked.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GPS Spoofing: Playwright live API test
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(2)
    @DisplayName("[Playwright] GPS spoofing + jamming → STOP within 150ms")
    void gpsSpoofingWithJamming_mustStopFast() {
        String payload = """
            {
              "id": "security-test-001",
              "ego_vehicle": {"speed_mps": 20.0, "acceleration_mps2": 0.0,
                              "heading_deg": 90.0, "lane_position": "center"},
              "environment": {"weather": "clear", "visibility_m": 100.0,
                              "road_condition": "dry", "lighting": "day"},
              "traffic_signals": {"state": "GREEN", "distance_m": 80.0, "time_to_change_s": 15.0},
              "objects": [],
              "security_context": {
                "spoofing_attack": "gps",
                "signal_jamming": true,
                "replay_attack": false,
                "data_injection": false
              }
            }
            """;

        APIResponse response = apiContext.post("/api/v1/decision",
            RequestOptions.create().setData(payload));

        assertEquals(200, response.status(),
            "API must return 200 for valid security scenario");

        String body = response.text();
        assertTrue(body.contains("\"action\""),
            "Response must contain 'action' field");

        // Parse response
        try {
            var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            var decision = mapper.readTree(body);

            String action = decision.get("action").asText();
            int responseMs = decision.get("response_time_ms").asInt();

            assertEquals("STOP", action,
                String.format("GPS spoofing + jamming must result in STOP. Got: %s", action));

            assertTrue(responseMs <= 150,
                String.format("ASIL-D timing violation: %dms > 150ms limit", responseMs));

            System.out.printf("  ✅ GPS spoofing → STOP in %dms%n", responseMs);

        } catch (Exception e) {
            fail("Failed to parse decision response: " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Replay Attack: Playwright API test
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(3)
    @DisplayName("[Playwright] Replay attack → must not CONTINUE")
    void replayAttack_mustNotContinue() {
        String payload = """
            {
              "id": "security-test-002",
              "ego_vehicle": {"speed_mps": 15.0, "acceleration_mps2": 0.0,
                              "heading_deg": 0.0, "lane_position": "center"},
              "environment": {"weather": "clear", "visibility_m": 150.0,
                              "road_condition": "dry", "lighting": "day"},
              "traffic_signals": {"state": "GREEN", "distance_m": 50.0, "time_to_change_s": 10.0},
              "objects": [],
              "security_context": {
                "spoofing_attack": "none",
                "signal_jamming": false,
                "replay_attack": true,
                "data_injection": false
              }
            }
            """;

        APIResponse response = apiContext.post("/api/v1/decision",
            RequestOptions.create().setData(payload));
        assertEquals(200, response.status());

        try {
            var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            var decision = mapper.readTree(response.text());
            String action = decision.get("action").asText();

            assertNotEquals("CONTINUE", action,
                "Replay attack detected — vehicle must not CONTINUE. " +
                "This tests CERT_INT30_C: integer overflow in replay timestamp check");

            System.out.printf("  ✅ Replay attack → %s (not CONTINUE)%n", action);

        } catch (Exception e) {
            fail("Parse error: " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Camera spoofing in fog — compound scenario
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(4)
    @DisplayName("[Playwright] Camera spoof + fog + pedestrian → STOP")
    void cameraSpoofFogPedestrian_mustStop() {
        String payload = """
            {
              "id": "security-test-003",
              "ego_vehicle": {"speed_mps": 18.0, "acceleration_mps2": 0.0,
                              "heading_deg": 45.0, "lane_position": "center"},
              "environment": {"weather": "fog", "visibility_m": 15.0,
                              "road_condition": "wet", "lighting": "night"},
              "traffic_signals": {"state": "YELLOW", "distance_m": 30.0, "time_to_change_s": 3.0},
              "objects": [
                {"id": "obj_1", "type": "pedestrian", "distance_m": 6.0,
                 "relative_speed_mps": 1.5, "lane_overlap": true,
                 "trajectory": "crossing"}
              ],
              "security_context": {
                "spoofing_attack": "camera",
                "signal_jamming": false,
                "replay_attack": false,
                "data_injection": false
              }
            }
            """;

        APIResponse response = apiContext.post("/api/v1/decision",
            RequestOptions.create().setData(payload));
        assertEquals(200, response.status());

        try {
            var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            var decision = mapper.readTree(response.text());
            String action   = decision.get("action").asText();
            int responseMs  = decision.get("response_time_ms").asInt();
            String alert    = decision.get("alert_level").asText();

            assertEquals("STOP", action,
                "Camera spoof + fog + close pedestrian = highest risk compound scenario → must STOP");
            assertEquals("critical", alert,
                "Alert level must be critical for compound attack scenario");
            assertTrue(responseMs <= 150,
                String.format("ASIL-D timing: %dms > 150ms", responseMs));

            System.out.printf("  ✅ Compound attack scenario → %s (alert=%s) in %dms%n",
                action, alert, responseMs);

        } catch (Exception e) {
            fail("Parse error: " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bulk: all loaded security results must have alerts
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(5)
    @DisplayName("[SAE-J3061] All security scenarios must have non-null alert level")
    void allSecurityScenarios_haveAlertLevel() {
        List<ScenarioResult> noAlert = securityResults.stream()
            .filter(r -> r.decision == null
                      || r.decision.alertLevel == null
                      || "none".equals(r.decision.alertLevel))
            .filter(ScenarioResult::isUnderSecurityAttack)
            .toList();

        if (!noAlert.isEmpty()) {
            fail(String.format(
                "%d attack scenarios returned alert_level=none. " +
                "SAE J3061 requires driver/system notification on all attacks.",
                noAlert.size()));
        }
        System.out.printf("  ✅ All %d attacked scenarios produced alerts%n",
            securityResults.stream().filter(ScenarioResult::isUnderSecurityAttack).count());
    }
}
