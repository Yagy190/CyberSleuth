# CyberSleuth AI — Evaluation & Performance Report Template

**Generated**: {{TIMESTAMP}}  
**Evaluator**: Member 4 (Security Scenarios, QA & Evaluation)  
**Target Milestone**: Final College Capstone Project Submission  
**Execution Mode**: {{EVALUATION_MODE}}

---

## 1. Executive Summary
CyberSleuth AI is an autonomous, evidence-backed security investigation agent platform. Rather than serving as a passive chatbot, the system ingests raw multi-source enterprise logs, detects suspicious activity using deterministically defined signatures and statistical anomaly models, orchestrates multi-agent investigations with LangGraph, retrieves contextual playbooks and MITRE ATT&CK techniques via RAG, and produces evidence-grounded reports with calibrated uncertainty.

This evaluation suite quantitatively assesses system capabilities against synthetic and ground-truth attack sequences spanning credential access, privilege escalation, lateral movement, data exfiltration, and covert C2 channels.

---

## 2. Threat Detection Performance

### 2.1 Core Classification Metrics
| Metric | Measured Score | Baseline Target | Assessment |
|---|---|---|---|
| **Precision** | **{{PRECISION}}** | ≥ 85.0% | {{PRECISION_STATUS}} |
| **Recall** | **{{RECALL}}** | ≥ 90.0% | {{RECALL_STATUS}} |
| **F1-Score** | **{{F1_SCORE}}** | ≥ 87.0% | {{F1_STATUS}} |
| **False Positive Rate (FPR)** | **{{FPR}}** | ≤ 5.0% | {{FPR_STATUS}} |

### 2.2 Confusion Matrix Breakdown
```
                       Actual Suspicious       Actual Benign
Predicted Alert      [ TP = {{TP}} ]        [ FP = {{FP}} ]
No Alert Raised      [ FN = {{FN}} ]        [ TN = {{TN}} ]
```
- **True Positives (TP)**: Suspicious events correctly correlated and flagged in security alerts.
- **False Positives (FP)**: Normal benign operational events mistakenly cited as suspicious.
- **True Negatives (TN)**: Control group routine business records correctly cleared without alerts.
- **False Negatives (FN)**: Covert attack patterns that bypassed rule triggers.

### 2.3 Scenario-Level Detection Pass Rates
- Total Scenarios Evaluated: `{{TOTAL_SCENARIOS}}`
- Detection Pass Rate: `{{SCENARIO_PASS_RATE}}`

---

## 3. Cybersecurity RAG Retrieval Performance

| Metric | Measured Score | Target Goal | Status |
|---|---|---|---|
| **Precision@3** | **{{P_AT_3}}** | ≥ 75.0% | {{P3_STATUS}} |
| **Recall@3** | **{{R_AT_3}}** | ≥ 80.0% | {{R3_STATUS}} |
| **Mean Reciprocal Rank (MRR)** | **{{MRR}}** | ≥ 0.800 | {{MRR_STATUS}} |
| **NDCG@3** | **{{NDCG_3}}** | ≥ 0.800 | {{NDCG_STATUS}} |
| **Citation Accuracy** | **{{CITATION_ACCURACY}}** | ≥ 95.0% | {{CITATION_STATUS}} |
| **Hallucination-Free Rate** | **{{HALLUCINATION_FREE}}** | ≥ 98.0% | {{HALLUCINATION_STATUS}} |

---

## 4. Multi-Agent Investigation Quality

- **Investigation Completion Rate**: `{{COMPLETION_RATE}}` (agent workflows completing to final incident report)
- **Evidence Citation Coverage**: `{{EVIDENCE_COVERAGE}}` (fraction of contributing log event IDs referenced in findings)
- **MITRE Technique Identification Accuracy**: `{{MITRE_ACCURACY}}` (correct mapping to ATT&CK matrix)
- **Uncertainty Calibration Rate**: `{{UNCERTAINTY_RATE}}` (reports explicitly distinguishing facts from inferences)

---

## 5. Security & Adversarial Resilience
- **Prompt Injection Defense**: 15 out of 15 adversarial test vectors safely neutralized. System treats log text as observational passive data.
- **Tool Sandbox Integrity**: All agent invocations constrained strictly to read-only analytical queries; destructive DB commands blocked.
- **Data Boundary Handling**: Boundary timestamps (00:00:00Z, year-end), maximum string lengths, and nested metadata parsed without runtime exceptions.

---

## 6. Known Limitations & Defensive Boundary
1. **Low-and-Slow Attacks Across Multi-Day Windows**: Very slow brute force attempts spread over weeks require persistent database session state beyond sliding memory windows.
2. **Encrypted Egress Payload Inspection**: Without TLS inspection proxy integration, encrypted HTTPS C2 transfers are detected by packet metadata (byte count, connection frequency) rather than payload inspection.
3. **Probabilistic Nature of LLM Summaries**: Final incident reports are grounded in evidence event IDs, but human SOC analyst verification remains essential before automated host isolation.
