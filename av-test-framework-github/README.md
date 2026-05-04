# Autonomous Vehicle Safety Test Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Java](https://img.shields.io/badge/Java-17-orange.svg)](https://openjdk.org/)
[![Playwright](https://img.shields.io/badge/Playwright-1.40-green.svg)](https://playwright.dev/)

**AI-augmented test framework for autonomous vehicle decision systems with automated MISRA C:2012 and CERT C compliance validation.**

---

## 🚗 Overview

End-to-end testing framework that validates autonomous vehicle safety and security decision-making under adversarial conditions. Generates AI-biased test scenarios weighted toward high-risk edge cases (fog, GPS spoofing, sensor jamming) and automatically validates against automotive safety standards.

**Key Features:**
- 🤖 **AI-biased scenario generation** — 30% fog scenarios vs. 20% uniform baseline, 40% critical severity
- 🛡️ **Automated compliance validation** — ISO 26262 ASIL-D, SAE J3061, MISRA C:2012, CERT C
- 🔐 **Cybersecurity attack testing** — GPS spoofing, replay attacks, signal jamming, camera injection
- 📊 **Audit trail generation** — compliance_report.json mapping violations to specific safety rules
- ⚡ **Playwright API testing** — Live HTTP calls with JSON payloads for decision engine validation

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Java 17+ (OpenJDK)
- Maven 3.9+
- Eclipse IDE (or IntelliJ)

### Installation

**1. Clone repository:**
\`\`\`bash
git clone https://github.com/YOUR_USERNAME/av-test-framework.git
cd av-test-framework
\`\`\`

**2. Install Python dependencies:**
\`\`\`bash
pip install requests
\`\`\`

**3. Install Playwright browsers:**
\`\`\`bash
mvn exec:java -e -D exec.mainClass=com.microsoft.playwright.CLI -D exec.args="install chromium"
\`\`\`

**4. Import into Eclipse:**
- File → Import → Maven → Existing Maven Projects
- Browse to av-test-framework → Finish

### Run Tests

**Terminal 1 — Start mock API:**
\`\`\`bash
python src/main/python/decision_engine_server.py
\`\`\`

**Terminal 2 — Generate & run:**
\`\`\`bash
python src/main/python/scenario_generator.py --total 100 --critical 25
python src/main/python/scenario_runner.py
mvn test
\`\`\`

---

## 📊 Test Coverage

| Standard | Rule | Validation |
|----------|------|------------|
| ISO 26262 ASIL-D | Critical proximity → STOP | Object <8m + lane overlap |
| ISO 26262 | Response time ≤150ms | ASIL-D timing requirement |
| SAE J3061 | Security attack response | No CONTINUE under attack |
| MISRA C:2012 15.5 | Single exit point | One decision per scenario |
| CERT INT30-C | Unsigned wrap | Replay timestamp validation |
| CERT INT32-C | Signed overflow | Deceleration 0–8 m/s² |

---

## 📁 Project Structure

\`\`\`
av-test-framework/
├── pom.xml
├── compliance/MISRA/*.md, CERT/*.md
├── scenarios/scenarios.json
├── results/results.json
├── reports/compliance_report.json
├── src/
│   ├── main/
│   │   ├── java/com/avtest/api/
│   │   └── python/
│   └── test/java/com/avtest/
\`\`\`

---

## 🔬 Technical Highlights

### AI-Biased Scenario Generation

\`\`\`python
WEATHER_WEIGHTS = {
    "clear": 0.20,   # Underweight normal conditions
    "fog":   0.30,   # Overweight adversarial
    "rain":  0.25
}
\`\`\`

Ensures coverage focuses on edge cases where AV systems fail.

### Rule-Based Expected Behavior

\`\`\`python
if object_distance < 8 and lane_overlap:
    action = "STOP"
    response_ms = 150  # ASIL-D requirement
\`\`\`

Each scenario carries deterministic expected behavior derived from ISO 26262.

---

## 🐛 Intentional Bugs

Mock engine contains 3 bugs to validate framework:
1. Replay attack → BRAKE (should STOP) — CERT INT30-C violation
2. Timing spikes >150ms — ISO 26262 ASIL-D violation
3. Fog+speed handling ✅ (works correctly)

Tests catch #1 and #2.

---

## 📝 License

MIT

---

## 📧 Contact

**Rishu Mishra**  
mishrarishu17@gmail.com  
[LinkedIn](https://linkedin.com/in/rishu-mishra-9a31b265)

---

**Built for safer autonomous vehicles** 🚗
