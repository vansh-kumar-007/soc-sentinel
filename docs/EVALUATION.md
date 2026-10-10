# Detection Evaluation

Status: **Phase 6 implementation in progress; benchmark labels and evaluator are committed, final CI verification pending.**

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

The versioned benchmark is [data/evaluation/benchmark.json](../data/evaluation/benchmark.json). It contains 19 scenarios and 73 unique event records covering the three shipped rules:

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
- **F1:** 2 × precision × recall / (precision + recall); `null` when undefined.

Reports contain scenario-level outcomes, per-rule and aggregate metrics, unexpected detections, missed expectations, evidence IDs, rule/dataset SHA-256 fingerprints, and a deterministic Markdown rendering. Wall-clock timestamps are omitted so identical inputs produce byte-stable substantive reports.

## Interpreting results and tuning candidates

The benchmark deliberately includes two hard negative examples:

- Repeated benign mistyped-password failures can still satisfy DET-001's count-and-window condition. This is an inherent ambiguity in the available fields, not evidence that the ground truth should be changed.
- A benign-looking argument such as `-EncodedCommandlet` can contain the text `-EncodedCommand`. If the current DET-003 predicate uses substring matching, it may alert even though the intended switch token is absent. This is a rule-tuning candidate: consider token-boundary-aware matching in a separately reviewed change, with regression tests for valid casing and benign lookalikes. Phase 6 does not silently alter production rules.

The expected output of this first benchmark is therefore not assumed to be perfect. The evaluation command is designed to surface mismatches so they can be reviewed as detection-engineering findings.

## Fingerprints and repeatability

- Dataset fingerprint: SHA-256 of the exact benchmark file bytes.
- Rule-set fingerprint: SHA-256 over lexically ordered YAML filenames and contents, with separators between each filename/content pair.
- Scenarios use fixed UTC timestamps and stable IDs.
- The report contains no generation timestamp; it is fully reproducible for identical input bytes, rules, and code behavior.
- Alerts come from the production `evaluate_events()` function. The evaluation package does not implement detection predicates.

## Limitations

This is a small, deliberately selected synthetic benchmark, not a random sample of production traffic. The positive/negative mix is artificial; benchmark precision is not an estimate of production precision. The dataset cannot model sensor outages, identity resolution, real-world user behavior, telemetry prevalence, adversarial adaptation, or analyst adjudication. These metrics demonstrate reproducible evaluation mechanics and identify specific rule behavior worth investigating; they do not prove real-world SOC performance.

Runtime/throughput measurements are not included in this phase because credible performance claims require a separately specified workload, hardware, warm-up, and measurement method.
