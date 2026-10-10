"""Tests for deterministic benchmark validation, matching, metrics, and reports."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from soc_sentinel.cli import main
from soc_sentinel.evaluation import (
    EvaluationError,
    calculate_metrics,
    evaluate_dataset,
    render_markdown,
    write_reports,
)

ROOT = Path(__file__).parents[1]
DATASET = ROOT / "data" / "evaluation" / "benchmark.json"
RULES = ROOT / "rules"


def read_benchmark() -> dict[str, Any]:
    return json.loads(DATASET.read_text(encoding="utf-8"))


def write_benchmark(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "benchmark.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def test_benchmark_validates_and_exposes_known_rule_limitations() -> None:
    report = evaluate_dataset(DATASET, RULES)
    assert report["dataset"]["scenario_count"] == 19
    assert report["dataset"]["event_count"] == 75
    assert report["rules"]["rule_ids"] == ["DET-001", "DET-002", "DET-003"]
    assert report["aggregate"]["tp"] >= 8
    assert report["aggregate"]["fp"] >= 2
    assert report["aggregate"]["fn"] == 0
    assert report["aggregate"]["tp"] == 10
    assert report["aggregate"]["fp"] == 2
    assert report["aggregate"]["tn"] == 46
    assert report["aggregate"]["precision"] == 0.833333
    assert report["aggregate"]["recall"] == 1.0
    assert report["aggregate"]["f1"] == 0.909091
    assert report["summary"]["false_positive_count"] == report["aggregate"]["fp"]
    assert report["summary"]["false_negative_count"] == 0
    assert {item["scenario_id"] for item in report["false_positives"]} >= {
        "auth-benign-mistyped-passwords",
        "process-encoded-substring-lookalike",
    }


def test_expected_labels_are_not_embedded_in_event_records() -> None:
    dataset = read_benchmark()
    for scenario in dataset["scenarios"]:
        for event in scenario["events"]:
            assert "scenario" not in event
            assert "expected_rule_ids" not in event
            assert "ground_truth" not in event


def test_identical_runs_produce_identical_reports_and_fingerprints() -> None:
    first = evaluate_dataset(DATASET, RULES)
    second = evaluate_dataset(DATASET, RULES)
    assert first == second
    assert first["dataset"]["fingerprint_sha256"] == second["dataset"]["fingerprint_sha256"]
    assert first["rules"]["fingerprint_sha256"] == second["rules"]["fingerprint_sha256"]


def test_zero_denominators_are_null() -> None:
    metrics = calculate_metrics(Counter())
    assert metrics == {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
        "precision": None,
        "recall": None,
        "f1": None,
    }


def test_precision_recall_and_f1_use_documented_counts() -> None:
    metrics = calculate_metrics(Counter({"tp": 6, "fp": 2, "fn": 3, "tn": 10}))
    assert metrics["precision"] == 0.75
    assert metrics["recall"] == 0.666667
    assert metrics["f1"] == 0.705882
    assert metrics["tn"] == 10


def test_duplicate_scenario_ids_are_rejected(tmp_path: Path) -> None:
    data = read_benchmark()
    data["scenarios"].append(data["scenarios"][0])
    with pytest.raises(EvaluationError, match="duplicate scenario_id"):
        evaluate_dataset(write_benchmark(tmp_path, data), RULES)


def test_duplicate_event_ids_are_rejected_and_replay_has_explicit_semantics(
    tmp_path: Path,
) -> None:
    data = read_benchmark()
    data["scenarios"][0]["events"].append(data["scenarios"][0]["events"][0])
    with pytest.raises(EvaluationError, match="duplicate event_id"):
        evaluate_dataset(write_benchmark(tmp_path, data), RULES)
    report = evaluate_dataset(DATASET, RULES)
    replayed = next(
        item for item in report["scenario_results"]
        if item["scenario_id"] == "cross-rule-out-of-order-and-replay"
    )
    assert replayed["outcome"] == "pass"


def test_unknown_rule_and_unknown_evidence_references_are_rejected(tmp_path: Path) -> None:
    data = read_benchmark()
    data["scenarios"][0]["expected_detections"][0]["rule_id"] = "DET-999"
    with pytest.raises(EvaluationError, match="missing rule DET-999"):
        evaluate_dataset(write_benchmark(tmp_path, data), RULES)

    data = read_benchmark()
    data["scenarios"][0]["expected_detections"][0]["evidence_event_ids"] = ["not-an-event"]
    with pytest.raises(EvaluationError, match="references unknown event IDs"):
        evaluate_dataset(write_benchmark(tmp_path, data), RULES)


def test_invalid_event_and_embedded_ground_truth_are_rejected(tmp_path: Path) -> None:
    data = read_benchmark()
    data["scenarios"][0]["events"][0]["source_ip"] = "999.999.999.999"
    with pytest.raises(EvaluationError, match="invalid event"):
        evaluate_dataset(write_benchmark(tmp_path, data), RULES)

    data = read_benchmark()
    data["scenarios"][0]["events"][0]["attributes"] = {"ground_truth": "benign"}
    with pytest.raises(EvaluationError, match="embeds reserved evaluation metadata"):
        evaluate_dataset(write_benchmark(tmp_path, data), RULES)


def test_duplicate_evidence_constraints_are_rejected(tmp_path: Path) -> None:
    data = read_benchmark()
    evidence = data["scenarios"][0]["expected_detections"][0]["evidence_event_ids"]
    evidence.append(evidence[0])
    with pytest.raises(EvaluationError, match="evidence_event_ids must not contain duplicates"):
        evaluate_dataset(write_benchmark(tmp_path, data), RULES)


def test_one_alert_cannot_satisfy_two_expectations(tmp_path: Path) -> None:
    data = read_benchmark()
    scenario = data["scenarios"][0]
    original = scenario["expected_detections"][0]
    duplicate = {
        "expectation_id": "second-independent-expectation",
        "rule_id": original["rule_id"],
        "evidence_event_ids": list(original["evidence_event_ids"]),
    }
    scenario["expected_detections"].append(duplicate)
    report = evaluate_dataset(write_benchmark(tmp_path, data), RULES)
    result = next(item for item in report["scenario_results"] if item["scenario_id"] == scenario["scenario_id"])
    assert len(result["matched_detections"]) == 1
    assert len(result["missed_detections"]) == 1
    assert report["aggregate"]["fn"] == 1


def test_malformed_json_and_duplicate_object_keys_are_rejected(tmp_path: Path) -> None:
    malformed = tmp_path / "broken.json"
    malformed.write_text("{not-json", encoding="utf-8")
    with pytest.raises(EvaluationError, match="invalid UTF-8 JSON"):
        evaluate_dataset(malformed, RULES)

    duplicate_key = tmp_path / "duplicate-key.json"
    duplicate_key.write_text('{"dataset_version":1,"dataset_version":1}', encoding="utf-8")
    with pytest.raises(EvaluationError, match="duplicate JSON object key"):
        evaluate_dataset(duplicate_key, RULES)


def test_report_json_markdown_and_fingerprints_are_stable(tmp_path: Path) -> None:
    report = evaluate_dataset(DATASET, RULES)
    json_path, markdown_path = write_reports(report, tmp_path / "reports")
    first_json = json_path.read_text(encoding="utf-8")
    first_markdown = markdown_path.read_text(encoding="utf-8")
    write_reports(report, tmp_path / "reports")
    assert json_path.read_text(encoding="utf-8") == first_json
    assert markdown_path.read_text(encoding="utf-8") == first_markdown
    assert json.loads(first_json) == report
    assert "Synthetic benchmark only" in first_markdown
    assert "False positives / unexpected alerts" in first_markdown
    assert "Rule-set SHA-256" in first_markdown
    assert render_markdown(report) == first_markdown


def test_missing_rules_path_returns_clear_evaluation_error() -> None:
    with pytest.raises(EvaluationError, match="cannot load detection rules"):
        evaluate_dataset(DATASET, ROOT / "does-not-exist")


def test_cli_writes_reports_and_returns_success_for_completed_measurement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "reports"
    code = main([
        "evaluate",
        "--dataset",
        str(DATASET),
        "--rules",
        str(RULES),
        "--output",
        str(output),
    ])
    assert code == 0
    stdout = capsys.readouterr().out
    assert "Precision:" in stdout
    assert (output / "evaluation.json").is_file()
    assert (output / "evaluation.md").is_file()


def test_cli_can_fail_on_benchmark_mismatches(tmp_path: Path) -> None:
    assert main([
        "evaluate",
        "--dataset",
        str(DATASET),
        "--rules",
        str(RULES),
        "--output",
        str(tmp_path / "reports"),
        "--fail-on-mismatch",
    ]) == 3


def test_cli_invalid_dataset_returns_configuration_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing.json"
    assert main(["evaluate", "--dataset", str(missing), "--output", str(tmp_path / "out")]) == 2
    assert "evaluation failed:" in capsys.readouterr().err


def test_per_rule_metrics_identify_specific_false_positive_sources() -> None:
    report = evaluate_dataset(DATASET, RULES)
    by_rule = {item["rule_id"]: item for item in report["per_rule"]}
    assert (by_rule["DET-001"]["tp"], by_rule["DET-001"]["fp"], by_rule["DET-001"]["fn"]) == (
        5,
        1,
        0,
    )
    assert (by_rule["DET-002"]["tp"], by_rule["DET-002"]["fp"], by_rule["DET-002"]["fn"]) == (
        2,
        0,
        0,
    )
    assert (by_rule["DET-003"]["tp"], by_rule["DET-003"]["fp"], by_rule["DET-003"]["fn"]) == (
        3,
        1,
        0,
    )


def test_expectation_ids_must_be_unique_across_the_dataset(tmp_path: Path) -> None:
    data = read_benchmark()
    duplicate = dict(data["scenarios"][0]["expected_detections"][0])
    data["scenarios"][1]["expected_detections"].append(duplicate)
    with pytest.raises(EvaluationError, match="duplicate expectation_id"):
        evaluate_dataset(write_benchmark(tmp_path, data), RULES)


def test_unknown_dataset_metadata_is_rejected(tmp_path: Path) -> None:
    data = read_benchmark()
    data["labels_generated_by_detector"] = True
    with pytest.raises(EvaluationError, match="invalid evaluation dataset"):
        evaluate_dataset(write_benchmark(tmp_path, data), RULES)


def test_duplicate_evidence_in_actual_alert_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime

    import soc_sentinel.evaluation as evaluation
    from soc_sentinel.detection.engine import Alert
    from soc_sentinel.detection.rules import Severity

    duplicate_evidence_alert = Alert(
        alert_id="alert-duplicate-evidence",
        rule_id="DET-001",
        rule_title="Authentication failure burst",
        severity=Severity.HIGH,
        first_observed=datetime(2026, 10, 10, tzinfo=UTC),
        last_observed=datetime(2026, 10, 10, tzinfo=UTC),
        event_count=2,
        evidence_event_ids=["burst-1", "burst-1"],
        grouping_context={"username": "alex.rivera", "source_ip": "192.0.2.10"},
        rationale="Synthetic malformed alert for evaluator integrity testing.",
        mitre_attack=["T1110"],
    )
    monkeypatch.setattr(evaluation, "evaluate_events", lambda events, rules: [duplicate_evidence_alert])
    with pytest.raises(EvaluationError, match="duplicate evidence IDs"):
        evaluate_dataset(DATASET, RULES)
