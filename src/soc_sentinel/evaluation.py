"""Reproducible evaluation of existing SOC Sentinel detection rules.

Ground truth lives in the benchmark document, never in events passed to the engine.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from soc_sentinel.detection.engine import Alert, evaluate_events
from soc_sentinel.detection.rules import DetectionRule, RuleValidationError, load_rules
from soc_sentinel.schemas import SecurityEvent

REPORT_VERSION = 1
RESERVED_LABEL_KEYS = {
    "scenario",
    "scenario_id",
    "expected_rule_ids",
    "expected_detections",
    "ground_truth",
    "evaluation_label",
    "evaluation_labels",
    "truth_label",
}


class EvaluationError(ValueError):
    """Raised when an evaluation dataset or its execution is invalid."""


class ExpectedDetection(BaseModel):
    """One independently authored expectation, matched to at most one alert."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    expectation_id: str = Field(min_length=1, max_length=128)
    rule_id: str = Field(pattern=r"^DET-[0-9]{3,}$")
    evidence_event_ids: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_evidence(self) -> ExpectedDetection:
        if len(set(self.evidence_event_ids)) != len(self.evidence_event_ids):
            raise ValueError("evidence_event_ids must not contain duplicates")
        if any(not item.strip() for item in self.evidence_event_ids):
            raise ValueError("evidence_event_ids must be non-empty strings")
        return self


class EvaluationScenario(BaseModel):
    """A deterministic synthetic scenario with separately authored ground truth."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    scenario_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]+$")
    title: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=10, max_length=1000)
    category: str = Field(min_length=2, max_length=80)
    priority: Literal["low", "medium", "high", "critical"]
    investigation_objective: str = Field(min_length=10, max_length=1000)
    events: list[dict[str, Any]]
    expected_detections: list[ExpectedDetection] = Field(default_factory=list)
    replay_event_ids: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=10, max_length=1500)
    limitations: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_expectation_ids(self) -> EvaluationScenario:
        ids = [item.expectation_id for item in self.expected_detections]
        if len(ids) != len(set(ids)):
            raise ValueError("expectation_id values must be unique within a scenario")
        return self


class EvaluationDataset(BaseModel):
    """Versioned benchmark schema; unknown metadata fields are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    dataset_version: Literal[1]
    title: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=10, max_length=2000)
    ground_truth_policy: str = Field(min_length=10, max_length=2000)
    scenarios: list[EvaluationScenario] = Field(min_length=1)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _contains_reserved_label_key(value: Any) -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold()
            if normalized in RESERVED_LABEL_KEYS:
                return str(key)
            found = _contains_reserved_label_key(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _contains_reserved_label_key(child)
            if found is not None:
                return found
    return None


def _fingerprint_dataset(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fingerprint_rules(rule_path: Path) -> str:
    files = (
        sorted([*rule_path.glob("*.yaml"), *rule_path.glob("*.yml")])
        if rule_path.is_dir()
        else [rule_path]
    )
    digest = hashlib.sha256()
    for file_path in files:
        try:
            payload = file_path.read_bytes()
        except OSError as exc:
            raise EvaluationError(f"cannot fingerprint rule file {file_path}: {exc}") from exc
        digest.update(file_path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


def _load_dataset(dataset_path: str | Path) -> tuple[EvaluationDataset, bytes]:
    path = Path(dataset_path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvaluationError(f"cannot read evaluation dataset {path}: {exc}") from exc
    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"invalid UTF-8 JSON in {path}: {exc}") from exc
    try:
        dataset = EvaluationDataset.model_validate(decoded)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
            for item in exc.errors(include_url=False)
        )
        raise EvaluationError(f"invalid evaluation dataset: {details}") from exc
    return dataset, raw


def _validate_scenarios(
    dataset: EvaluationDataset, rules: list[DetectionRule]
) -> list[tuple[EvaluationScenario, list[SecurityEvent]]]:
    rule_by_id = {rule.rule_id: rule for rule in rules}
    seen_scenarios: set[str] = set()
    seen_events: set[str] = set()
    validated: list[tuple[EvaluationScenario, list[SecurityEvent]]] = []

    for scenario in dataset.scenarios:
        if scenario.scenario_id in seen_scenarios:
            raise EvaluationError(f"duplicate scenario_id: {scenario.scenario_id}")
        seen_scenarios.add(scenario.scenario_id)
        events: list[SecurityEvent] = []
        local_ids: set[str] = set()
        for index, payload in enumerate(scenario.events):
            reserved = _contains_reserved_label_key(payload)
            if reserved is not None:
                raise EvaluationError(
                    f"scenario {scenario.scenario_id} event {index} embeds reserved "
                    f"evaluation metadata key {reserved!r}; ground truth must stay outside events"
                )
            try:
                event = SecurityEvent.model_validate(payload)
            except ValidationError as exc:
                details = "; ".join(
                    f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
                    for item in exc.errors(include_url=False)
                )
                raise EvaluationError(
                    f"invalid event in scenario {scenario.scenario_id} at index {index}: {details}"
                ) from exc
            if event.event_id in local_ids or event.event_id in seen_events:
                raise EvaluationError(
                    f"duplicate event_id {event.event_id!r}; use replay_event_ids to model "
                    "replayed input without duplicating ground-truth records"
                )
            local_ids.add(event.event_id)
            seen_events.add(event.event_id)
            events.append(event)

        for replay_id in scenario.replay_event_ids:
            if replay_id not in local_ids:
                raise EvaluationError(
                    f"scenario {scenario.scenario_id} replays unknown event_id {replay_id!r}"
                )
        for expected in scenario.expected_detections:
            rule = rule_by_id.get(expected.rule_id)
            if rule is None:
                raise EvaluationError(
                    f"scenario {scenario.scenario_id} expects missing rule {expected.rule_id}"
                )
            if not rule.enabled:
                raise EvaluationError(
                    f"scenario {scenario.scenario_id} expects disabled rule {expected.rule_id}"
                )
            missing_evidence = set(expected.evidence_event_ids) - local_ids
            if missing_evidence:
                raise EvaluationError(
                    f"expectation {expected.expectation_id} references unknown event IDs: "
                    f"{', '.join(sorted(missing_evidence))}"
                )
        validated.append((scenario, events))
    return validated


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _metrics(counts: Counter[str]) -> dict[str, int | float | None]:
    tp = counts["tp"]
    fp = counts["fp"]
    fn = counts["fn"]
    tn = counts["tn"]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    if precision is None or recall is None or precision + recall == 0:
        f1 = None
    else:
        f1 = round(2 * precision * recall / (precision + recall), 6)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1}


def _alert_summary(alert: Alert) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "severity": alert.severity.value,
        "evidence_event_ids": list(alert.evidence_event_ids),
        "rationale": alert.rationale,
        "first_observed": alert.first_observed.isoformat().replace("+00:00", "Z"),
        "last_observed": alert.last_observed.isoformat().replace("+00:00", "Z"),
    }


def evaluate_dataset(
    dataset_path: str | Path = "data/evaluation/benchmark.json",
    rules_path: str | Path = "rules",
) -> dict[str, Any]:
    """Validate a benchmark and evaluate it using the production detection engine.

    TP/FN count independently authored expected detection instances. FP counts unmatched
    actual alert instances. TN counts negative scenario-rule opportunities with no alert;
    TN is supplemental and is not used in precision, recall, or F1 denominators.
    """
    dataset, raw_dataset = _load_dataset(dataset_path)
    try:
        rules = load_rules(rules_path)
    except RuleValidationError as exc:
        raise EvaluationError(f"cannot load detection rules: {exc}") from exc
    if not rules:
        raise EvaluationError("rule loader returned no rules")
    validated = _validate_scenarios(dataset, rules)
    enabled_rules = sorted((rule for rule in rules if rule.enabled), key=lambda rule: rule.rule_id)
    if not enabled_rules:
        raise EvaluationError("no enabled detection rules are available for evaluation")

    totals: Counter[str] = Counter()
    rule_counts: dict[str, Counter[str]] = {
        rule.rule_id: Counter() for rule in enabled_rules
    }
    rule_titles = {rule.rule_id: rule.title for rule in enabled_rules}
    scenario_results: list[dict[str, Any]] = []
    all_false_positives: list[dict[str, Any]] = []
    all_false_negatives: list[dict[str, Any]] = []

    for scenario, events in validated:
        replay_events = [event for event in events if event.event_id in scenario.replay_event_ids]
        alerts = evaluate_events([*events, *replay_events], rules)
        unmatched_alerts = list(sorted(alerts, key=lambda item: (item.rule_id, item.alert_id)))
        expected = sorted(scenario.expected_detections, key=lambda item: item.expectation_id)
        matched_expectations: list[dict[str, Any]] = []
        missed_expectations: list[dict[str, Any]] = []

        for expectation in expected:
            candidates = [
                alert for alert in unmatched_alerts
                if alert.rule_id == expectation.rule_id
                and set(expectation.evidence_event_ids).issubset(alert.evidence_event_ids)
            ]
            if candidates:
                candidates.sort(
                    key=lambda alert: (
                        set(alert.evidence_event_ids) != set(expectation.evidence_event_ids),
                        alert.alert_id,
                    )
                )
                matched = candidates[0]
                unmatched_alerts.remove(matched)
                matched_expectations.append({
                    "expectation_id": expectation.expectation_id,
                    "rule_id": expectation.rule_id,
                    "evidence_event_ids": list(expectation.evidence_event_ids),
                    "alert_id": matched.alert_id,
                    "actual_evidence_event_ids": list(matched.evidence_event_ids),
                })
                rule_counts[expectation.rule_id]["tp"] += 1
                totals["tp"] += 1
            else:
                missed = {
                    "expectation_id": expectation.expectation_id,
                    "rule_id": expectation.rule_id,
                    "evidence_event_ids": list(expectation.evidence_event_ids),
                    "reason": "No unmatched alert from the expected rule contained all expected evidence IDs.",
                }
                missed_expectations.append(missed)
                all_false_negatives.append({"scenario_id": scenario.scenario_id, **missed})
                rule_counts[expectation.rule_id]["fn"] += 1
                totals["fn"] += 1

        scenario_false_positives: list[dict[str, Any]] = []
        for alert in unmatched_alerts:
            item = {
                "scenario_id": scenario.scenario_id,
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "evidence_event_ids": list(alert.evidence_event_ids),
                "rationale": alert.rationale,
                "reason": (
                    "Unexpected alert: no remaining ground-truth expectation matched its "
                    "rule and evidence references."
                ),
            }
            scenario_false_positives.append(item)
            all_false_positives.append(item)
            rule_counts[alert.rule_id]["fp"] += 1
            totals["fp"] += 1

        expected_rule_ids = {item.rule_id for item in expected}
        actual_rule_ids = {item.rule_id for item in alerts}
        for rule in enabled_rules:
            rule_id = rule.rule_id
            if rule_id not in expected_rule_ids and rule_id not in actual_rule_ids:
                rule_counts[rule_id]["tn"] += 1
                totals["tn"] += 1

        if missed_expectations and scenario_false_positives:
            outcome = "mixed"
        elif missed_expectations:
            outcome = "missed"
        elif scenario_false_positives:
            outcome = "unexpected"
        else:
            outcome = "pass"
        scenario_results.append({
            "scenario_id": scenario.scenario_id,
            "title": scenario.title,
            "category": scenario.category,
            "priority": scenario.priority,
            "description": scenario.description,
            "investigation_objective": scenario.investigation_objective,
            "expected_detections": [
                {
                    "expectation_id": item.expectation_id,
                    "rule_id": item.rule_id,
                    "evidence_event_ids": list(item.evidence_event_ids),
                }
                for item in expected
            ],
            "matched_detections": matched_expectations,
            "missed_detections": missed_expectations,
            "actual_alerts": [_alert_summary(alert) for alert in alerts],
            "unexpected_detections": scenario_false_positives,
            "true_negative_rule_opportunities": sum(
                1 for rule in enabled_rules
                if rule.rule_id not in expected_rule_ids and rule.rule_id not in actual_rule_ids
            ),
            "outcome": outcome,
            "rationale": scenario.rationale,
            "limitations": list(scenario.limitations),
        })

    per_rule = []
    for rule in enabled_rules:
        counts = rule_counts[rule.rule_id]
        per_rule.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            **_metrics(counts),
        })

    return {
        "report_version": REPORT_VERSION,
        "dataset": {
            "title": dataset.title,
            "path": Path(dataset_path).as_posix(),
            "fingerprint_sha256": _fingerprint_dataset(raw_dataset),
            "scenario_count": len(dataset.scenarios),
            "event_count": sum(len(scenario.events) for scenario in dataset.scenarios),
            "replay_count": sum(len(scenario.replay_event_ids) for scenario in dataset.scenarios),
            "ground_truth_policy": dataset.ground_truth_policy,
        },
        "rules": {
            "path": Path(rules_path).as_posix(),
            "fingerprint_sha256": _fingerprint_rules(Path(rules_path)),
            "enabled_rule_count": len(enabled_rules),
            "rule_ids": [rule.rule_id for rule in enabled_rules],
        },
        "metric_definitions": {
            "evaluation_unit": (
                "One expected detection is a positive unit. Each expected detection can match "
                "at most one alert from the same rule whose evidence contains every expected "
                "evidence event ID. Unmatched expectations are FN; unmatched alert instances "
                "are FP. TN is a separate supplemental count of scenario-rule opportunities "
                "with neither an expectation nor an alert."
            ),
            "precision": "TP / (TP + FP); null if denominator is zero.",
            "recall": "TP / (TP + FN); null if denominator is zero.",
            "f1": "2 * precision * recall / (precision + recall); null if undefined.",
            "tn": "Count of negative scenario-rule opportunities with no alert; not used in P/R/F1.",
            "determinism": (
                "No wall-clock timestamp is included. JSON and Markdown content are stable for "
                "identical dataset bytes, rule bytes, and software behavior."
            ),
        },
        "aggregate": _metrics(totals),
        "per_rule": per_rule,
        "scenario_results": scenario_results,
        "false_positives": all_false_positives,
        "false_negatives": all_false_negatives,
        "summary": {
            "scenario_count": len(scenario_results),
            "passing_scenarios": sum(item["outcome"] == "pass" for item in scenario_results),
            "scenarios_with_misses": sum(item["outcome"] in {"missed", "mixed"} for item in scenario_results),
            "scenarios_with_unexpected_alerts": sum(
                item["outcome"] in {"unexpected", "mixed"} for item in scenario_results
            ),
            "false_positive_count": len(all_false_positives),
            "false_negative_count": len(all_false_negatives),
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Render a deterministic Markdown report from the canonical report object."""
    aggregate = report["aggregate"]
    dataset = report["dataset"]
    rules = report["rules"]
    lines = [
        "# SOC Sentinel Detection Evaluation",
        "",
        "> Synthetic benchmark only. These measurements are not evidence of real-world SOC performance.",
        "",
        f"- Dataset: {dataset['title']}",
        f"- Scenarios: {dataset['scenario_count']} · source events: {dataset['event_count']} · replayed inputs: {dataset['replay_count']}",
        f"- Enabled rules: {rules['enabled_rule_count']} ({', '.join(rules['rule_ids'])})",
        f"- Dataset SHA-256: {dataset['fingerprint_sha256']}",
        f"- Rule-set SHA-256: {rules['fingerprint_sha256']}",
        "",
        "## Aggregate metrics",
        "",
        "| TP | FP | FN | TN* | Precision | Recall | F1 |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        f"| {aggregate['tp']} | {aggregate['fp']} | {aggregate['fn']} | {aggregate['tn']} | {_fmt(aggregate['precision'])} | {_fmt(aggregate['recall'])} | {_fmt(aggregate['f1'])} |",
        "",
        "*TN counts negative scenario-rule opportunities with no alert. It is supplemental and is not used in precision, recall, or F1 denominators. TP/FN count expected detection instances; FP counts unmatched actual alert instances.",
        "",
        "## Per-rule results",
        "",
        "| Rule | TP | FP | FN | TN* | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report["per_rule"]:
        lines.append(
            f"| {item['rule_id']} — {_cell(item['title'])} | {item['tp']} | {item['fp']} | "
            f"{item['fn']} | {item['tn']} | {_fmt(item['precision'])} | "
            f"{_fmt(item['recall'])} | {_fmt(item['f1'])} |"
        )
    lines.extend(["", "## Scenario outcomes", "", "| Scenario | Category | Outcome | Expected | Matched | Missed | Unexpected |", "|---|---|---|---:|---:|---:|---:|"])
    for item in report["scenario_results"]:
        lines.append(
            f"| {item['scenario_id']} — {_cell(item['title'])} | {_cell(item['category'])} | "
            f"{item['outcome']} | {len(item['expected_detections'])} | "
            f"{len(item['matched_detections'])} | {len(item['missed_detections'])} | "
            f"{len(item['unexpected_detections'])} |"
        )
    lines.extend(["", "## False positives / unexpected alerts", ""])
    if report["false_positives"]:
        for item in report["false_positives"]:
            lines.append(
                f"- **{item['scenario_id']} / {item['rule_id']}** — alert {item['alert_id']}; "
                f"evidence: {', '.join(item['evidence_event_ids'])}. {item['reason']}"
            )
    else:
        lines.append("None.")
    lines.extend(["", "## False negatives / missed expectations", ""])
    if report["false_negatives"]:
        for item in report["false_negatives"]:
            lines.append(
                f"- **{item['scenario_id']} / {item['rule_id']}** — expected evidence: "
                f"{', '.join(item['evidence_event_ids'])}. {item['reason']}"
            )
    else:
        lines.append("None.")
    lines.extend([
        "",
        "## Interpretation and limitations",
        "",
        "Ground truth is independently authored benchmark metadata and is not passed to the detection engine. Each expectation is matched to at most one alert by stable rule ID and evidence references. Replayed input is modeled separately from the unique source-event records and follows the production engine's first-event-wins de-duplication behavior.",
        "",
        "A small synthetic dataset can reveal obvious boundary errors, lookalike false positives, and rule-specific gaps, but it cannot represent production telemetry diversity, identity ambiguity, logging loss, adversarial adaptation, or prevalence. Precision in this benchmark depends on its deliberately selected positive/negative mix and must not be generalized to a real SOC.",
        "",
    ])
    return "\n".join(lines)


def _fmt(value: float | None) -> str:
    return "null" if value is None else f"{value:.4f}"


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def write_reports(report: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    """Write stable JSON and Markdown artifacts; no generated database is created."""
    target = Path(output_dir)
    try:
        target.mkdir(parents=True, exist_ok=True)
        json_path = target / "evaluation.json"
        markdown_path = target / "evaluation.md"
        json_payload = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        markdown_payload = render_markdown(report)
        json_path.write_text(json_payload, encoding="utf-8")
        markdown_path.write_text(markdown_payload, encoding="utf-8")
    except OSError as exc:
        raise EvaluationError(f"cannot write evaluation reports to {target}: {exc}") from exc
    return json_path, markdown_path
