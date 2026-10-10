# Evaluation Plan

Status: **planned — no detection or performance metrics have been measured in Phase 1.**

## Goals

- Verify expected alerts on labeled positive synthetic scenarios.
- Measure false positives on labeled benign scenarios.
- Test event ordering and time-window boundaries deterministically.
- Track runtime on repeatable workloads without presenting local benchmarks as universal performance claims.

## Metrics

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * precision * recall / (precision + recall), when the denominator is non-zero.

The implementation must define behavior for undefined denominators and report TP, FP, and FN counts alongside ratios.

Potential operational measurements include events per second and detection latency. These require documented hardware, dataset size, warm-up, and commands.

## Test data

Use small, deterministic, synthetic event fixtures. Do not commit private telemetry or personal data. Every scenario should state expected detections and known limitations.

## Acceptance principle

A rule is not evaluated merely because it fires on one hand-picked positive case. Include benign cases, boundary cases, malformed inputs, and reproducible instructions.
