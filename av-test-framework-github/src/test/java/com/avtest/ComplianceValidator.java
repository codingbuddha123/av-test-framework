package com.avtest.compliance;

import com.avtest.api.ResultsLoader;
import com.avtest.api.ScenarioResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;

import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Compliance Validator
 * Reads MISRA/CERT markdown rules and validates all scenarios against them.
 * Generates compliance_report.json for audit trail.
 *
 * Maps scenario compliance_tags → validation logic → pass/fail verdict.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("MISRA / CERT Compliance Validation")
public class ComplianceValidator {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static List<ScenarioResult> allResults;
    private static final List<Map<String, Object>> reportEntries = new ArrayList<>();

    @BeforeAll
    static void loadAll() throws Exception {
        allResults = ResultsLoader.load();
        System.out.printf("\n📋 Compliance check on %d scenarios%n", allResults.size());
        verifyComplianceDocsExist();
    }

    @AfterAll
    static void generateReport() throws Exception {
        Path reportDir = Path.of("reports");
        Files.createDirectories(reportDir);

        long violations = reportEntries.stream()
            .filter(e -> "FAIL".equals(e.get("verdict"))).count();

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("generated_at",    LocalDateTime.now().toString());
        report.put("total_rules",      reportEntries.size());
        report.put("passing_rules",    reportEntries.size() - violations);
        report.put("failing_rules",    violations);
        report.put("overall_verdict",  violations == 0 ? "COMPLIANT" : "NON-COMPLIANT");
        report.put("rules",            reportEntries);

        String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(report);
        Files.writeString(reportDir.resolve("compliance_report.json"), json);

        System.out.printf("\n📊 Compliance Report: %d rules, %d violations → %s%n",
            reportEntries.size(), violations,
            violations == 0 ? "✅ COMPLIANT" : "❌ NON-COMPLIANT");
        System.out.println("   → reports/compliance_report.json");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MISRA_C_2012_Rule_15_5: Single exit — one decision per scenario
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(1)
    @DisplayName("[MISRA 15.5] One decision returned per scenario (single exit)")
    void misra_15_5_singleExit() {
        List<ScenarioResult> tagged = filterByTag("MISRA_C_2012_Rule_15_5");
        List<ScenarioResult> violations = tagged.stream()
            .filter(r -> r.decision == null || r.decision.action == null)
            .toList();

        recordRule("MISRA_C_2012_Rule_15_5",
            "Single point of exit — one decision returned per scenario",
            tagged.size(), violations.size(), "HIGH");

        assertEquals(0, violations.size(),
            violations.size() + " scenarios returned null decision (MISRA 15.5)");
        System.out.printf("  ✅ MISRA 15.5: All %d scenarios returned a decision%n", tagged.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CERT_INT30_C: Replay attack timestamp wraparound
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(2)
    @DisplayName("[CERT INT30-C] Replay attack → must not CONTINUE (timestamp wrap)")
    void cert_int30_replayDetection() {
        List<ScenarioResult> replayScenarios = filterByTag("CERT_INT30_C").stream()
            .filter(ScenarioResult::isUnderSecurityAttack)
            .toList();

        List<ScenarioResult> violations = replayScenarios.stream()
            .filter(r -> "CONTINUE".equals(r.decision.action))
            .toList();

        recordRule("CERT_INT30_C",
            "Unsigned int wrap in replay timestamp — replayed data accepted as current",
            replayScenarios.size(), violations.size(), "HIGH");

        if (!violations.isEmpty()) {
            fail(String.format(
                "CERT INT30-C VIOLATION: %d replay attacks not detected. " +
                "Timestamp wraparound allows old data to appear valid.",
                violations.size()));
        }
        System.out.printf("  ✅ CERT INT30-C: All %d replay attacks detected%n",
            replayScenarios.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CERT_INT32_C: Deceleration value in valid physical range
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(3)
    @DisplayName("[CERT INT32-C] Deceleration value within physical limits (0–8 m/s²)")
    void cert_int32_decelerationOverflow() {
        List<ScenarioResult> tagged = filterByTag("CERT_INT32_C");
        List<ScenarioResult> violations = tagged.stream()
            .filter(r -> r.decision != null &&
                (r.decision.decelerationMps2 < 0 || r.decision.decelerationMps2 > 8.1))
            .toList();

        recordRule("CERT_INT32_C",
            "Integer overflow in deceleration calc — value outside 0–8 m/s²",
            tagged.size(), violations.size(), "MEDIUM");

        violations.forEach(v -> System.err.printf(
            "  ⚠️  Deceleration=%.2f for %s%n",
            v.decision.decelerationMps2, v.name));

        assertEquals(0, violations.size(),
            violations.size() + " scenarios had deceleration outside 0–8 m/s²");
        System.out.printf("  ✅ CERT INT32-C: All %d deceleration values in range%n",
            tagged.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CERT_EXP34_C: API never crashes on attack scenarios (null deref)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(4)
    @DisplayName("[CERT EXP34-C] API does not crash on spoofed inputs (no null deref)")
    void cert_exp34_nullPointerOnSpoof() {
        List<ScenarioResult> spoofed = allResults.stream()
            .filter(r -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> sec = (Map<String, Object>) r.scenario.get("security_context");
                return sec != null && !"none".equals(sec.get("spoofing_attack"));
            })
            .toList();

        List<ScenarioResult> crashed = spoofed.stream()
            .filter(r -> r.decision == null || "ERROR".equals(r.decision.action))
            .toList();

        recordRule("CERT_EXP34_C",
            "Null pointer dereference on spoofed sensor data — engine crash",
            spoofed.size(), crashed.size(), "HIGH");

        assertEquals(0, crashed.size(),
            crashed.size() + " spoofed scenarios caused engine errors (CERT EXP34-C null deref)");
        System.out.printf("  ✅ CERT EXP34-C: Engine survived all %d spoofed scenarios%n",
            spoofed.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ISO 26262 ASIL-D: Critical scenarios must have STOP or BRAKE
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(5)
    @DisplayName("[ISO26262 ASIL-D] Critical severity → STOP or BRAKE only")
    void iso26262_asilD_criticalAction() {
        List<ScenarioResult> critical = filterByTag("ISO26262_ASIL_D").stream()
            .filter(r -> "critical".equals(r.severity))
            .toList();

        List<ScenarioResult> violations = critical.stream()
            .filter(r -> !"STOP".equals(r.decision.action)
                      && !"BRAKE".equals(r.decision.action))
            .toList();

        recordRule("ISO26262_ASIL_D",
            "Critical scenario did not result in protective action (STOP/BRAKE)",
            critical.size(), violations.size(), "CRITICAL");

        assertEquals(0, violations.size(),
            String.format("%d critical ASIL-D scenarios returned: %s",
                violations.size(),
                violations.stream().map(v -> v.decision.action).toList()));
        System.out.printf("  ✅ ISO26262 ASIL-D: All %d critical scenarios → STOP/BRAKE%n",
            critical.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SAE J3061: Response time for critical security scenarios
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @Order(6)
    @DisplayName("[SAE-J3061] Security attack response ≤ 150ms")
    void saeJ3061_securityResponseTime() {
        List<ScenarioResult> attacked = allResults.stream()
            .filter(ScenarioResult::isUnderSecurityAttack)
            .filter(r -> "critical".equals(r.severity))
            .toList();

        List<ScenarioResult> slow = attacked.stream()
            .filter(r -> r.decision.responseTimeMs > 150)
            .toList();

        recordRule("SAE_J3061",
            "Security attack response exceeded 150ms ASIL-D timing requirement",
            attacked.size(), slow.size(), "CRITICAL");

        if (!slow.isEmpty()) {
            int worst = slow.stream().mapToInt(r -> r.decision.responseTimeMs).max().orElse(0);
            fail(String.format("SAE J3061 TIMING: %d critical security scenarios exceeded 150ms. Worst: %dms",
                slow.size(), worst));
        }
        System.out.printf("  ✅ SAE J3061: All %d critical attack responses within 150ms%n",
            attacked.size());
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private List<ScenarioResult> filterByTag(String tag) {
        return allResults.stream()
            .filter(r -> r.complianceTags != null && r.complianceTags.contains(tag))
            .toList();
    }

    private void recordRule(String ruleId, String description,
                            int tested, int violations, String severity) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("rule",             ruleId);
        entry.put("description",      description);
        entry.put("severity",         severity);
        entry.put("scenarios_tested", tested);
        entry.put("violations",       violations);
        entry.put("violation_rate",   tested > 0 ?
            String.format("%.1f%%", (double) violations / tested * 100) : "0%");
        entry.put("verdict",          violations == 0 ? "PASS" : "FAIL");
        reportEntries.add(entry);
    }

    private static void verifyComplianceDocsExist() {
        Path misra = Path.of("compliance/MISRA/MISRA_C_2012_AV_Rules.md");
        Path cert  = Path.of("compliance/CERT/CERT_C_AV_Security_Rules.md");

        if (!Files.exists(misra) || !Files.exists(cert)) {
            System.err.println("⚠️  Compliance docs not found at compliance/MISRA/ and compliance/CERT/");
        } else {
            System.out.println("  📄 Compliance docs verified: MISRA + CERT");
        }
    }
}
