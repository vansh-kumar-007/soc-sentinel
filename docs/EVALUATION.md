# Detection Evaluation

Status: **Phase 6 complete and verified.** The implementation baseline was independently verified by [GitHub Actions run #252](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38152063404) for commit [`e4fbbc9783a5224c5215e6616e915891cccf1116`](https://github.com/vansh-kumar-007/soc-sentinel/commit/e4fbbc9783a5224c5215e6616e915891cccf1116). All three Python jobs completed successfully: 120 tests per version, Ruff lint, Ruff formatting, and mypy on Python 3.11, 3.12, and 3.13. The Python 3.11 job also passed shipped-rule validation, ran the production evaluator on the committed benchmark (TP 10, FP 2, FN 0, supplemental TN 46; precision 0.833333, recall 1.000000, F1 0.909091), and uploaded both reports as artifact `detection-evaluation-e4fbbc9783a5224c5215e6616e915891cccf1116`. Phase 7 changed DET-003 to require a standalone encoded-command switch token. The corrected implementation passed [CI run #261](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38157188277) on feature commit [`8fbb74bee426030d85a064a8277f9dfc01a875a7`](https://github.com/vansh-kumar-007/soc-sentinel/commit/8fbb74bee426030d85a064a8277f9dfc01a875a7): 122 tests, Ruff lint/format, and mypy passed on Python 3.11, 3.12, and 3.13; Python 3.11 also passed rule validation and the production evaluation CLI. The report artifact is available from that run. The report narrative and benchmark metadata were clarified in commit [`183ab840641567ca789174a114679e5581426cb0`](https://github.com/vansh-kumar-007/soc-sentinel/commit/183ab840641567ca789174a114679e5581426cb0); CI is being rerun on the updated head.

## Phase 7 comparison

The Phase 6 baseline was TP 10, FP 2, FN 0, supplemental TN 46, precision 0.833333, recall 1.000000, and F1 0.909091. The production evaluator measured Phase 7 at TP 10, FP 1, FN 0, supplemental TN 47, precision 0.909091, recall 1.000000, and F1 0.952381. The `process-encoded-substring-lookalike` scenario now passes with no DET-003 alert, while all three expected DET-003 detections remain matched. The benchmark's negative label, event, and expected detections were not changed. DET-001 is intentionally unchanged because five failed logins alone cannot distinguish benign mistypes from malicious activity.

## Reproduce the evaluation

From the repository root:

```bash
python -m pip install -e ".[dev,dashboard]"
soc-sentinel validate-rules --rules rules/
soc-sentinel evaluate --dataset data/evaluation/benchmark.json --rules rules/ --output reports/evaluation/
```

The command writes deterministic `evaluation.json` and `evaluation.md` reports to the output directory. The report directory is generated locally and should not be committed. Add `--json` to print the complete canonical JSON report to stdout. Add `--fail-on-mismatch` to return exit code 3 when any false positive or false negative is measured. A completed measurement returns 0 by default even when it identifies rule defects; validation/configuration errors return 2.

The evaluation module has no Streamlit dependency and does not access the database, correlation service, incident lifecycle, or external services. The optional dashboard reads the same evaluator output and displays its metrics without implementing a second metric engine.

## Benchmark and ground truth

The versioned benchmark is [data/evaluation/benchmark.json](../data/evaluation/benchmark.json). It contains 19 scenarios and 75 unique event records covering the three shipped rules:

- Authentication bursts: threshold boundary, below-threshold activity, outside-window events, missing source IP, exact grouping, two independent groups, benign mistyped-password behavior, and failures/success ordering.
- Process execution: encoded-command switch, case variation, ordinary PowerShell, missing command-line telemetry, benign `-Encoding` lookalike, and a substring lookalike.
- Cross-rule: independent rule matches in one mixed scenario, deliberately out-of-order records, and explicit replay of a previously listed event ID.

All identities are fictional. IPs are drawn from documentation ranges. The process command lines are inert strings and are never executed.

Expected detection labels, rationale, and expected evidence IDs are stored only in the evaluation dataset's scenario metadata. They are not copied into event objects. The evaluator rejects event records containing reserved ground-truth metadata, validates every event through the existing `SecurityEvent` model, checks global scenario/event/expectation uniqueness, verifies rule IDs and evidence references, and rejects malformed JSON, duplicate JSON object keys, and invalid metadata. Replay is represented by `replay_event_ids`; the unique source record remains singular, and the harness deliberately passes an additional copy to the existing engine to test its documented first-occurrence-wins behavior.

Ground truth is independently authored from the scenario's investigation objective and documented rule contract, not generated from observed alerts. Benign scenarios stay negative even if a rule fires. The evaluator must not modify expected outcomes just to make current rules score better.

## Matching semantics and metrics

The primary positive unit is an **expected detection instance**, identified by a stable expectation ID. A produced alert can satisfy at most one expectation. It must have the same rule ID and include every expected evidence event ID. The matcher prefers an exact evidence-set match, then uses stable alert IDs to break ties. Unmatched expectations are false negatives (FN); unmatched actual alert instances are false positives (FP). A rule ID alone is not sufficient to match an alert.

True negatives (TN) are reported as a supplemental count of negative scenario-rule opportunities where that scenario has no expectation for the rule and the rule emits no alert. This TN count has a different opportunity basis from the positive expectation/alert-instance counts and is **not used** in precision, recall, or F1. It must not be interpreted as a conventional fully balanced confusion matrix.

- **TP:** independently expected detection matched to one actual alert.
- **FP:** actual alert left unmatched after one-to-one expectation matching.
- **FN:** expected detection with no matching actual alert.
- **TN (supplemental):** scenario-rule pair with no expected detection and no actual alert.
- **Precision:** TP / (TP + FP); `null` when its denominator is zero.
- **Recall:** TP / (TP + FN); `null` when its denominator is zero.
- **F1:** 2 × TP / (2 × TP + FP + FN); `null` when its denominator is zero.

Reports contain scenario-level outcomes, per-rule and aggregate metrics, unexpected detections, missed expectations, evidence IDs, rule/dataset SHA-256 fingerprints, and a deterministic Markdown rendering. Wall-clock timestamps are omitted so identical inputs produce byte-stable substantive reports.

## Measured benchmark result

The committed synthetic benchmark measures:

| Rule | TP | FP | FN | TN* | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| DET-001 | 5 | 1 | 0 | 14 | 0.833333 | 1.000000 | 0.909091 |
| DET-002 | 2 | 0 | 0 | 17 | 1.000000 | 1.000000 | 1.000000 |
| DET-003 | 3 | 0 | 0 | 16 | 1.000000 | 1.000000 | 1.000000 |
| **Aggregate** | **10** | **1** | **0** | **47** | **0.909091** | **1.000000** | **0.952381** |

*TN is supplemental: it counts a negative scenario-rule opportunity with no alert and is not included in precision, recall, or F1. TP/FN count expected detection instances and FP counts unmatched alert instances, so TN is not a conventional balanced confusion-matrix count.

### False-positive details

- **`auth-benign-mistyped-passwords` / DET-001:** evidence `mistype-1`, `mistype-2`, `mistype-3`, `mistype-4`, `mistype-5`; all five failed logins belong to fictional account `pat.taylor` and source `192.0.2.45`. The benign typo ground truth is intentional and independent. The count-and-window detector cannot distinguish these failures from malicious activity based on available fields.

There were no false negatives on this constructed benchmark. Compared with Phase 6, Phase 7 removes the DET-003 false positive without losing genuine detections; the sole remaining false positive is DET-001 on the five benign mistyped-password events. These values are a regression result for the selected synthetic scenarios, not an estimate of real-world SOC precision or recall.

## Interpreting results and tuning candidates

The benchmark retains two important negative cases:

- Repeated benign mistyped-password failures can still satisfy DET-001's count-and-window condition. This is an inherent ambiguity in the available fields, not evidence that the ground truth should be changed.
- `-EncodedCommandlet` is a lookalike, not the intended switch. The Phase 7 `icontains_token` operator rejects it while preserving case-insensitive matching of standalone switches. The operator uses regex token boundaries; it is not a full PowerShell parser, does not decode payloads, and does not establish malicious intent.

The evaluator continues to report mismatches rather than changing ground-truth labels to improve scores.

## Fingerprints and repeatability

- Dataset fingerprint: SHA-256 of the exact benchmark file bytes.
- Rule-set fingerprint: SHA-256 over lexically ordered YAML filenames and contents, with separators between each filename/content pair.
- Scenarios use fixed UTC timestamps and stable IDs.
- The report contains no generation timestamp; it is fully reproducible for identical input bytes, rules, and code behavior.
- Alerts come from the production `evaluate_events()` function. The evaluation package does not implement detection predicates.

## Limitations

This is a small, deliberately selected synthetic benchmark, not a random sample of production traffic. The positive/negative mix is artificial; benchmark precision is not an estimate of production precision. The dataset cannot model sensor outages, identity resolution, real-world user behavior, telemetry prevalence, adversarial adaptation, or analyst adjudication. These metrics demonstrate reproducible evaluation mechanics and identify specific rule behavior worth investigating; they do not prove real-world SOC performance.

Runtime/throughput measurements are not included in this phase because credible performance claims require a separately specified workload, hardware, warm-up, and measurement method.
