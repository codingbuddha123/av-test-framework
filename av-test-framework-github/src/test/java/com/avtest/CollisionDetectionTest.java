package com.avtest;

import com.avtest.api.ResultsLoader;
import com.avtest.api.ScenarioResult;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Collision Detection Safety Tests
 * Validates AV decision-making for collision scenarios against MISRA/ISO 26262 rules.
 *
 * Tests consume results.json produced by the Python scenario runner.
 * Each test maps to one or more compliance requirements.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("AV Collision Detection — Safety Validation")
public class CollisionDetectionTest {

    private static List<ScenarioResult> allResults;
    private static List<ScenarioResult> collisionResults;

    @BeforeAll
    static void loadResults() throws Exception {
        allResults       = ResultsLoader.load();
        collisionResults = ResultsLoader.loadByCategory("collision");

        System.out.printf("\n📋 Loaded %d total results (%d collision scenarios)%n",
            allResults.size(), collisionResults.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ASIL-D: Critical proximity → mandatory STOP
    // Compliance: ISO26262_ASIL_D, MISRA_C_2012_Rule_15_5
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(1)
    @DisplayName("[ASIL-D] Object within 8m with lane overlap → STOP required")
    void criticalProximity_mustStop() {
        List<ScenarioResult> critical = collisionResults.stream()
            .filter(ScenarioResult::hasCriticalObject)
            .toList();

        assertFalse(critical.isEmpty(),
            "No critical proximity scenarios found — check scenario generation");

        List<ScenarioResult> violations = critical.stream()
            .filter(r -> !"STOP".equals(r.decision.action))
            .toList();

        if (!violations.isEmpty()) {
            StringBuilder msg = new StringBuilder(
                String.format("ASIL-D VIOLATION: %d/%d critical scenarios did NOT result in STOP:%n",
                    violations.size(), critical.size()));
            violations.forEach(v -> msg.append(String.format(
                "  • %s: got %s (dist=%.1fm)%n",
                v.name, v.decision.action, getMinObjectDistance(v))));
            fail(msg.toString());
        }

        System.out.printf("  ✅ All %d critical proximity scenarios → STOP%n", critical.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ISO 26262: Response time ≤ 150ms for ASIL-D critical scenarios
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(2)
    @DisplayName("[ISO26262] Critical response time ≤ 150ms")
    void criticalResponseTime_withinLimit() {
        List<ScenarioResult> criticalResults = allResults.stream()
            .filter(r -> "critical".equals(r.severity))
            .toList();

        List<ScenarioResult> slowResponses = criticalResults.stream()
            .filter(r -> r.decision.responseTimeMs > 150)
            .toList();

        if (!slowResponses.isEmpty()) {
            long count = slowResponses.size();
            int worst = slowResponses.stream()
                .mapToInt(r -> r.decision.responseTimeMs).max().orElse(0);

            fail(String.format(
                "ISO26262 TIMING VIOLATION: %d critical scenarios exceeded 150ms limit. Worst: %dms",
                count, worst));
        }

        System.out.printf("  ✅ All %d critical scenarios responded within 150ms%n",
            criticalResults.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fog + high speed → mandatory brake
    // Compliance: MISRA_C_2012_Rule_15_5
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(3)
    @DisplayName("[MISRA] Fog visibility <25m at speed >10mps → BRAKE or STOP required")
    void fogHighSpeed_mustBrake() {
        List<ScenarioResult> fogHighSpeed = allResults.stream()
            .filter(r -> "fog".equals(r.getWeather())
                      && r.getVisibility() < 25
                      && r.getEgoSpeed() > 10)
            .toList();

        if (fogHighSpeed.isEmpty()) {
            System.out.println("  ⚠️  No fog+high-speed scenarios — ensure generator produces these");
            return;
        }

        List<ScenarioResult> violations = fogHighSpeed.stream()
            .filter(r -> !"STOP".equals(r.decision.action)
                      && !"BRAKE".equals(r.decision.action))
            .toList();

        assertEquals(0, violations.size(),
            String.format("MISRA VIOLATION: %d fog+high-speed scenarios did not brake. " +
                "Got actions: %s", violations.size(),
                violations.stream().map(r -> r.decision.action).toList()));

        System.out.printf("  ✅ All %d fog+high-speed scenarios → BRAKE/STOP%n",
            fogHighSpeed.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Parameterized: every collision scenario validates its expected behavior
    // ─────────────────────────────────────────────────────────────────────────

    static Stream<ScenarioResult> collisionScenarios() throws Exception {
        return ResultsLoader.loadByCategory("collision").stream();
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("collisionScenarios")
    @Order(4)
    @DisplayName("[PARAM] Each collision scenario matches expected action")
    void eachScenario_matchesExpectedAction(ScenarioResult result) {
        assertNotNull(result.decision.action,
            "Decision action must not be null for: " + result.name);

        assertNotEquals("ERROR", result.decision.action,
            "API error for scenario: " + result.name);

        // Severity-based assertion
        if ("critical".equals(result.severity) && result.hasCriticalObject()) {
            assertEquals("STOP", result.decision.action,
                String.format("Critical severity with close object must STOP. Scenario: %s",
                    result.name));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Summary: overall pass rate must be ≥ 95%
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(5)
    @DisplayName("[SUMMARY] Overall collision pass rate ≥ 95%")
    void overallPassRate_aboveThreshold() {
        long total  = collisionResults.size();
        long passed = collisionResults.stream().filter(r -> r.validation.passed).count();
        double rate = total > 0 ? (double) passed / total * 100 : 0;

        System.out.printf("  📊 Collision pass rate: %.1f%% (%d/%d)%n", rate, passed, total);

        assertTrue(rate >= 95.0,
            String.format("Pass rate %.1f%% below 95%% threshold. %d failures.",
                rate, total - passed));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private double getMinObjectDistance(ScenarioResult r) {
        var objects = (java.util.List<java.util.Map<String, Object>>)
            r.scenario.get("objects");
        if (objects == null || objects.isEmpty()) return 999;
        return objects.stream()
            .mapToDouble(o -> ((Number) o.get("distance_m")).doubleValue())
            .min().orElse(999);
    }
}
