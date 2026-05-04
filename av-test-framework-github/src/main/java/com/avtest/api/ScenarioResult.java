package com.avtest.api;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * Maps the results.json structure produced by the Python runner.
 * Consumed by Playwright and JUnit validation tests.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScenarioResult {

    @JsonProperty("scenario_id")   public String scenarioId;
    @JsonProperty("name")          public String name;
    @JsonProperty("category")      public String category;
    @JsonProperty("severity")      public String severity;
    @JsonProperty("compliance_tags") public List<String> complianceTags;
    @JsonProperty("scenario")      public Map<String, Object> scenario;
    @JsonProperty("decision")      public Decision decision;
    @JsonProperty("validation")    public Validation validation;

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Decision {
        @JsonProperty("action")              public String action;
        @JsonProperty("alert_level")         public String alertLevel;
        @JsonProperty("deceleration_mps2")   public double decelerationMps2;
        @JsonProperty("response_time_ms")    public int responseTimeMs;
        @JsonProperty("confidence")          public double confidence;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Validation {
        @JsonProperty("passed")     public boolean passed;
        @JsonProperty("violations") public List<Violation> violations;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Violation {
        @JsonProperty("rule")        public String rule;
        @JsonProperty("compliance")  public String compliance;
        @JsonProperty("description") public String description;
        @JsonProperty("severity")    public String severity;
    }

    // ── Convenience helpers ──────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public double getEgoSpeed() {
        Map<String, Object> ego = (Map<String, Object>) scenario.get("ego_vehicle");
        return ego != null ? ((Number) ego.get("speed_mps")).doubleValue() : 0;
    }

    @SuppressWarnings("unchecked")
    public double getVisibility() {
        Map<String, Object> env = (Map<String, Object>) scenario.get("environment");
        return env != null ? ((Number) env.get("visibility_m")).doubleValue() : 999;
    }

    @SuppressWarnings("unchecked")
    public String getWeather() {
        Map<String, Object> env = (Map<String, Object>) scenario.get("environment");
        return env != null ? (String) env.get("weather") : "clear";
    }

    @SuppressWarnings("unchecked")
    public boolean hasCriticalObject() {
        List<Map<String, Object>> objects =
            (List<Map<String, Object>>) scenario.get("objects");
        if (objects == null) return false;
        return objects.stream().anyMatch(o ->
            ((Number) o.get("distance_m")).doubleValue() < 8.0 &&
            Boolean.TRUE.equals(o.get("lane_overlap"))
        );
    }

    @SuppressWarnings("unchecked")
    public boolean isUnderSecurityAttack() {
        Map<String, Object> sec = (Map<String, Object>) scenario.get("security_context");
        if (sec == null) return false;
        return !"none".equals(sec.get("spoofing_attack")) ||
               Boolean.TRUE.equals(sec.get("signal_jamming")) ||
               Boolean.TRUE.equals(sec.get("replay_attack"));
    }
}
