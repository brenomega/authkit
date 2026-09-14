#!/usr/bin/env python3
"""Generate targeted synthetic rule tests and routing payloads (not product metrics)."""
import datetime
import json
import pathlib
import sys
import yaml

root, output = map(pathlib.Path, sys.argv[1:])
output.mkdir(parents=True, exist_ok=True)
rules = yaml.safe_load((root / "k8s/06-prometheus-rules.yaml").read_text())["spec"]
(output / "rules.yml").write_text(yaml.safe_dump(rules, sort_keys=False))
by_name = {rule["alert"]: rule for group in rules["groups"] for rule in group["rules"]}
cases = [
    ("AuthKitFailedLoginSpike", "security_login_failed_total", {}, "0+20x20"),
    ("AuthKitGlobalRateLimiterRedisDegraded", 'security_infrastructure_failure_total{component="rate_limiter_redis"}',
     {"component": "rate_limiter_redis"}, "0+1x20"),
    *[("AuthKitKeyLifecycleFailure", f'security_key_lifecycle_failure_total{{family="{family}"}}',
       {"family": family}, "0+1x20") for family in ("signing", "jwks", "mfa")],
]
tests, alerts = [], []
for name, series, labels, values in cases:
    rule = by_name[name]
    assert rule["labels"]["severity"] == "critical", name
    assert (root / rule["annotations"]["runbook_url"]).is_file(), name
    expected = {"exp_labels": {**labels, "severity": "critical"}, "exp_annotations": rule["annotations"]}
    tests.append({"interval": "1m", "input_series": [{"series": series, "values": values}],
                  "alert_rule_test": [{"eval_time": "10m", "alertname": name, "exp_alerts": [expected]}]})
    tests.append({"interval": "1m", "input_series": [{"series": series, "values": "0x20"}],
                  "alert_rule_test": [{"eval_time": "10m", "alertname": name, "exp_alerts": []}]})
    alerts.append({"labels": {"alertname": name, "severity": "critical", **labels},
                   "annotations": rule["annotations"],
                   "startsAt": datetime.datetime.now(datetime.timezone.utc).isoformat()})
(output / "tests.yml").write_text(yaml.safe_dump({"rule_files": ["rules.yml"],
                                                "evaluation_interval": "1m", "tests": tests}, sort_keys=False))
(output / "routing-input.json").write_text(json.dumps(alerts, indent=2) + "\n")
