#!/usr/bin/env python3
"""
Detection-as-Code: Sigma Rule Validator
=========================================
Validates Sigma rules against positive (TP) and negative (TN) test log fixtures.
Produces a test report with TPR/FPR metrics for CI/CD pipeline consumption.

Usage:
    python validate_rules.py --rules rules/sigma/ --logs tests/logs/ --output report.json

Author: Detection Engineering Team
"""

import os
import re
import json
import yaml
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Any
from dataclasses import dataclass, field, asdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)


@dataclass
class TestResult:
    rule_id: str
    rule_title: str
    technique_id: str
    test_id: str
    expected: str        # ALERT | NO_ALERT
    actual: str          # ALERT | NO_ALERT
    passed: bool
    matched_fields: list = field(default_factory=list)
    failure_reason: str = ""


@dataclass
class RuleReport:
    rule_id: str
    rule_title: str
    technique_id: str
    level: str
    status: str
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    tpr: float = 0.0   # True Positive Rate (sensitivity)
    fpr: float = 0.0   # False Positive Rate
    test_results: list = field(default_factory=list)


class SigmaConditionEvaluator:
    """
    Lightweight Sigma condition evaluator.
    Supports: contains, endswith, startswith, contains|all, |re modifiers.
    For production use, replace with sigma-cli or pySigma.
    """

    def __init__(self, rule: dict):
        self.rule = rule
        self.detection = rule.get("detection", {})

    def _match_value(self, event_value: str, pattern: str, modifier: str = "") -> bool:
        """Match a single event field value against a Sigma pattern."""
        if not isinstance(event_value, str):
            event_value = str(event_value)

        # Case-insensitive by default (Sigma spec)
        ev = event_value.lower()
        pat = pattern.lower()

        if modifier == "re":
            return bool(re.search(pattern, event_value, re.IGNORECASE))
        elif modifier == "endswith":
            return ev.endswith(pat)
        elif modifier == "startswith":
            return ev.startswith(pat)
        else:  # default: contains
            return pat in ev

    def _match_field(self, event: dict, field_key: str, value_spec: Any) -> bool:
        """
        Match a Sigma field specification against an event.
        Handles field|modifier syntax and list/single value specs.
        """
        parts = field_key.split("|")
        field_name = parts[0]
        modifier = parts[1] if len(parts) > 1 else ""
        all_modifier = "all" in parts[2:] if len(parts) > 2 else False

        # Get field value from event (case-insensitive field lookup)
        event_val = None
        for k, v in event.items():
            if k.lower() == field_name.lower():
                event_val = v
                break

        if event_val is None:
            return False

        # Normalize value_spec to list
        if not isinstance(value_spec, list):
            value_spec = [value_spec]

        if all_modifier:
            # ALL values must match (AND logic)
            return all(self._match_value(str(event_val), str(v), modifier) for v in value_spec)
        else:
            # ANY value must match (OR logic)
            return any(self._match_value(str(event_val), str(v), modifier) for v in value_spec)

    def _evaluate_selection(self, event: dict, selection_name: str) -> tuple[bool, list]:
        """Evaluate a named selection block against the event."""
        selection = self.detection.get(selection_name, {})
        matched_fields = []

        for field_key, value_spec in selection.items():
            if not self._match_field(event, field_key, value_spec):
                return False, []
            matched_fields.append(field_key)

        return True, matched_fields

    def evaluate(self, event: dict) -> tuple[bool, list]:
        """
        Evaluate the full Sigma condition against an event.
        Returns (matched: bool, matched_fields: list)
        """
        condition_str = self.detection.get("condition", "")

        # Build a map of selection names -> results
        selection_results = {}
        selection_fields = {}
        for key in self.detection:
            if key == "condition":
                continue
            result, fields = self._evaluate_selection(event, key)
            selection_results[key] = result
            selection_fields[key] = fields

        # Parse condition expression
        # Supports: and, or, not, parentheses
        try:
            matched = self._parse_condition(condition_str, selection_results)
            matched_fields = []
            for sel_name, matched_flag in selection_results.items():
                if matched_flag:
                    matched_fields.extend(selection_fields.get(sel_name, []))
            return matched, matched_fields
        except Exception as e:
            log.warning(f"Condition parse error for '{condition_str}': {e}")
            return False, []

    def _parse_condition(self, condition: str, results: dict) -> bool:
        """Simple recursive descent condition parser."""
        # Normalize
        cond = condition.strip()

        # Replace selection names with their boolean values
        # Sort by length descending to avoid partial replacements
        for name in sorted(results.keys(), key=len, reverse=True):
            val = "True" if results[name] else "False"
            cond = re.sub(r'\b' + re.escape(name) + r'\b', val, cond)

        # Replace Sigma keywords with Python keywords
        cond = re.sub(r'\band\b', 'and', cond)
        cond = re.sub(r'\bor\b', 'or', cond)
        cond = re.sub(r'\bnot\b', 'not', cond)

        # Safe eval (only booleans and logical operators)
        if re.match(r'^[TrueFalse\s\(\)andornot]+$', cond):
            return eval(cond)
        return False


def load_rule(rule_path: Path) -> dict | None:
    """Load and parse a Sigma YAML rule file."""
    try:
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
        return rule
    except Exception as e:
        log.error(f"Failed to load rule {rule_path}: {e}")
        return None


def load_logs(log_path: Path) -> list[dict]:
    """Load test log events from a JSON file."""
    try:
        with open(log_path) as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data]
    except Exception as e:
        log.error(f"Failed to load logs {log_path}: {e}")
        return []


def extract_technique_id(rule: dict) -> str:
    """Extract ATT&CK technique ID from Sigma tags."""
    tags = rule.get("tags", [])
    for tag in tags:
        if tag.startswith("attack.t"):
            # Convert 'attack.t1059.001' -> 'T1059.001'
            return tag.replace("attack.", "").upper()
    return "UNKNOWN"


def find_matching_logs(technique_id: str, logs_dir: Path, log_type: str) -> list[tuple[Path, list[dict]]]:
    """Find test log files matching the technique ID."""
    results = []
    search_dir = logs_dir / log_type

    if not search_dir.exists():
        return results

    # Normalize: T1059.001 -> look for files with T1059 in the name
    base_technique = technique_id.split(".")[0].upper()

    for log_file in search_dir.glob("*.json"):
        name_upper = log_file.name.upper()
        if base_technique in name_upper or technique_id.replace(".", "_") in name_upper:
            events = load_logs(log_file)
            results.append((log_file, events))

    return results


def validate_rule(rule: dict, logs_dir: Path) -> RuleReport:
    """Run all test cases for a single Sigma rule."""
    technique_id = extract_technique_id(rule)
    report = RuleReport(
        rule_id=rule.get("id", "UNKNOWN"),
        rule_title=rule.get("title", "Untitled"),
        technique_id=technique_id,
        level=rule.get("level", "unknown"),
        status=rule.get("status", "unknown"),
    )

    evaluator = SigmaConditionEvaluator(rule)

    # Test against positive (TP) logs
    for log_file, events in find_matching_logs(technique_id, logs_dir, "positive"):
        for event in events:
            if event.get("_comment", "").startswith("//"):
                continue
            test_id = event.get("test_id", f"unnamed-{id(event)}")
            expected = event.get("expected_result", "ALERT")

            matched, matched_fields = evaluator.evaluate(event)
            actual = "ALERT" if matched else "NO_ALERT"
            passed = (actual == expected)

            result = TestResult(
                rule_id=report.rule_id,
                rule_title=report.rule_title,
                technique_id=technique_id,
                test_id=test_id,
                expected=expected,
                actual=actual,
                passed=passed,
                matched_fields=matched_fields,
                failure_reason="" if passed else f"Expected {expected}, got {actual}"
            )
            report.test_results.append(result)
            report.total_tests += 1

            if expected == "ALERT" and actual == "ALERT":
                report.true_positives += 1
                report.passed += 1
            elif expected == "ALERT" and actual == "NO_ALERT":
                report.false_negatives += 1
                report.failed += 1
                log.warning(f"  ❌ FN: {test_id} — rule missed a known-bad event")
            elif expected == "NO_ALERT" and actual == "NO_ALERT":
                report.true_negatives += 1
                report.passed += 1

    # Test against negative (TN) logs
    for log_file, events in find_matching_logs(technique_id, logs_dir, "negative"):
        for event in events:
            test_id = event.get("test_id", f"unnamed-{id(event)}")
            expected = event.get("expected_result", "NO_ALERT")

            matched, matched_fields = evaluator.evaluate(event)
            actual = "ALERT" if matched else "NO_ALERT"
            passed = (actual == expected)

            result = TestResult(
                rule_id=report.rule_id,
                rule_title=report.rule_title,
                technique_id=technique_id,
                test_id=test_id,
                expected=expected,
                actual=actual,
                passed=passed,
                matched_fields=matched_fields,
                failure_reason="" if passed else f"FALSE POSITIVE: {test_id} triggered on benign event"
            )
            report.test_results.append(result)
            report.total_tests += 1

            if expected == "NO_ALERT" and actual == "NO_ALERT":
                report.true_negatives += 1
                report.passed += 1
            elif expected == "NO_ALERT" and actual == "ALERT":
                report.false_positives += 1
                report.failed += 1
                log.warning(f"  ⚠️  FP: {test_id} — rule fired on benign event (matched: {matched_fields})")

    # Calculate rates
    tp = report.true_positives
    fn = report.false_negatives
    fp = report.false_positives
    tn = report.true_negatives

    report.tpr = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
    report.fpr = round(fp / (fp + tn), 3) if (fp + tn) > 0 else 0.0

    return report


def print_report_summary(reports: list[RuleReport]) -> bool:
    """Print a human-readable test summary. Returns True if all rules pass."""
    print("\n" + "=" * 70)
    print("  DETECTION-AS-CODE VALIDATION REPORT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)

    all_passed = True

    for report in reports:
        status_icon = "✅" if report.failed == 0 else "❌"
        print(f"\n{status_icon}  [{report.technique_id}] {report.rule_title}")
        print(f"     Rule ID : {report.rule_id}")
        print(f"     Level   : {report.level.upper()}")
        print(f"     Tests   : {report.total_tests} total | "
              f"{report.passed} passed | {report.failed} failed")
        print(f"     TPR     : {report.tpr:.1%}  |  FPR: {report.fpr:.1%}")

        if report.failed > 0:
            all_passed = False
            for result in report.test_results:
                if not result.passed:
                    print(f"       → {result.test_id}: {result.failure_reason}")

    print("\n" + "=" * 70)
    if all_passed:
        print("  🎉 ALL RULES PASSED — Safe to deploy")
    else:
        print("  🚨 VALIDATION FAILED — Do not deploy until all tests pass")
    print("=" * 70 + "\n")

    return all_passed


def main():
    parser = argparse.ArgumentParser(description="Sigma Rule Validator for Detection-as-Code CI/CD")
    parser.add_argument("--rules", default="rules/sigma", help="Path to Sigma rules directory")
    parser.add_argument("--logs", default="tests/logs", help="Path to test logs directory")
    parser.add_argument("--output", default="test_report.json", help="Output JSON report path")
    parser.add_argument("--fail-on-fp", action="store_true",
                        help="Fail pipeline if any false positives are detected")
    args = parser.parse_args()

    rules_dir = Path(args.rules)
    logs_dir = Path(args.logs)

    if not rules_dir.exists():
        log.error(f"Rules directory not found: {rules_dir}")
        exit(1)

    rule_files = sorted(rules_dir.glob("*.yml"))
    if not rule_files:
        log.error("No Sigma rule files found")
        exit(1)

    log.info(f"Found {len(rule_files)} rule(s) to validate")

    reports = []
    for rule_file in rule_files:
        log.info(f"Validating: {rule_file.name}")
        rule = load_rule(rule_file)
        if rule:
            report = validate_rule(rule, logs_dir)
            reports.append(report)
            log.info(f"  TPR={report.tpr:.1%} | FPR={report.fpr:.1%} | "
                     f"Tests={report.total_tests} | Passed={report.passed} | Failed={report.failed}")

    all_passed = print_report_summary(reports)

    # Write JSON report for CI/CD artifact consumption
    report_data = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_rules": len(reports),
        "all_passed": all_passed,
        "summary": {
            "total_tests": sum(r.total_tests for r in reports),
            "passed": sum(r.passed for r in reports),
            "failed": sum(r.failed for r in reports),
            "true_positives": sum(r.true_positives for r in reports),
            "false_negatives": sum(r.false_negatives for r in reports),
            "false_positives": sum(r.false_positives for r in reports),
        },
        "rules": [asdict(r) for r in reports]
    }

    with open(args.output, "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    log.info(f"Report written to {args.output}")

    # Exit code for CI/CD
    if not all_passed:
        exit(1)

    if args.fail_on_fp:
        total_fps = sum(r.false_positives for r in reports)
        if total_fps > 0:
            log.error(f"Pipeline failing: {total_fps} false positive(s) detected")
            exit(1)

    exit(0)


if __name__ == "__main__":
    main()
