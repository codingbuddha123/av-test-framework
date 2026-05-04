package com.avtest.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Loads results.json produced by the Python scenario runner.
 * Used by all JUnit/Playwright test classes.
 */
public class ResultsLoader {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DEFAULT_PATH = "results/results.json";

    public static List<ScenarioResult> load() throws IOException {
        return load(DEFAULT_PATH);
    }

    public static List<ScenarioResult> load(String path) throws IOException {
        File file = new File(path);
        if (!file.exists()) {
            throw new IllegalStateException(
                "results.json not found at: " + file.getAbsolutePath() +
                "\nRun: python src/main/python/scenario_runner.py first"
            );
        }

        JsonNode root = MAPPER.readTree(file);
        JsonNode resultsNode = root.get("results");

        List<ScenarioResult> results = new ArrayList<>();
        if (resultsNode != null && resultsNode.isArray()) {
            for (JsonNode node : resultsNode) {
                results.add(MAPPER.treeToValue(node, ScenarioResult.class));
            }
        }
        return results;
    }

    public static List<ScenarioResult> loadBySeverity(String severity) throws IOException {
        return load().stream()
            .filter(r -> severity.equalsIgnoreCase(r.severity))
            .collect(Collectors.toList());
    }

    public static List<ScenarioResult> loadByCategory(String category) throws IOException {
        return load().stream()
            .filter(r -> category.equalsIgnoreCase(r.category))
            .collect(Collectors.toList());
    }

    public static List<ScenarioResult> loadFailed() throws IOException {
        return load().stream()
            .filter(r -> !r.validation.passed)
            .collect(Collectors.toList());
    }
}
