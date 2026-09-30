import json
from dataclasses import replace
from pathlib import Path

from cloudsheriff import engine


NOW = "2026-09-29T00:00:00Z"


def previous(finding, *, status=None, hash_value=None, gone=False):
    record = engine.diff({}, [finding], {finding.check_id}, NOW)[1][finding.key]
    if status is not None:
        record["last_status"] = status
    if hash_value is not None:
        record["evidence_hash"] = hash_value
    record["gone"] = gone
    return {finding.key: record}


def test_normalize_reads_structured_fields_only():
    raw = json.loads(Path("tests/fixtures/prowler_demo.ocsf.json").read_text())
    item = engine.normalize(raw)[0]
    assert item.status == "PASS" and item.severity == "high"
    assert item.resource_name == "cs-demo-admin"  # real Prowler puts the SG id in resources[0].name
    assert item.labels == ("Name:cs-demo-admin", "Environment:production")
    assert item.compliance == {"CIS-7.0": ["6.3", "6.4"]}  # only the targeted benchmark
    assert "message" not in item.__dict__


def test_normalize_skips_missing_resources():
    assert engine.normalize([{"resources": []}]) == []


def test_finding_key_is_stable():
    assert engine.finding_key("a", "b", "c", "d") == engine.finding_key("a", "b", "c", "d")


def test_finding_key_changes_for_each_part():
    base = engine.finding_key("a", "b", "c", "d")
    assert len({base, engine.finding_key("x", "b", "c", "d"), engine.finding_key("a", "x", "c", "d"), engine.finding_key("a", "b", "x", "d"), engine.finding_key("a", "b", "c", "x")}) == 5


def test_sg_id_from_uid():
    assert engine.sg_id_from_uid("arn:x:security-group/sg-123") == "sg-123"
    assert engine.sg_id_from_uid("arn:x:instance/i-123") is None


def test_canonical_rules_filters_maps_sorts_and_deduplicates():
    rules = [
        {"IsEgress": True, "IpProtocol": "tcp", "FromPort": 1, "ToPort": 1, "CidrIpv4": "x"},
        {"IsEgress": False, "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv4": "0.0.0.0/0", "SecurityGroupRuleId": "x", "Description": "a"},
        {"IsEgress": False, "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv4": "0.0.0.0/0", "Description": "b"},
        {"IsEgress": False, "IpProtocol": "-1", "ReferencedGroupInfo": {"GroupId": "sg-2"}},
        {"IsEgress": False, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "PrefixListId": "pl-1"},
        {"IsEgress": False, "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIpv6": "::/0"},
    ]
    result = engine.canonical_sg_rules(rules)
    assert len(result) == 4
    assert result[0]["src"] == "sg:sg-2"
    assert {r["src"] for r in result} == {"sg:sg-2", "0.0.0.0/0", "::/0", "pl:pl-1"}


def test_description_change_does_not_change_hash():
    base = {"IsEgress": False, "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv4": "0.0.0.0/0"}
    one = {"ingress": engine.canonical_sg_rules([{**base, "Description": "a"}])}
    two = {"ingress": engine.canonical_sg_rules([{**base, "Description": "b"}])}
    assert engine.evidence_hash(one) == engine.evidence_hash(two)


def test_attach_evidence_only_security_groups(finding):
    other = finding(key="other", resource_uid="arn:aws:ec2:::instance/i-1")
    attached, untouched = engine.attach_evidence([finding(), other], {"sg-1": []})
    assert attached.evidence == {"ingress": []} and attached.evidence_hash
    assert untouched == other


def test_diff_row_1_new_fail(finding):
    t, u = engine.diff({}, [finding(status="FAIL")], {"check"}, NOW)
    assert (t[0].evaluation, t[0].lifecycle, t[0].change) == ("FAIL", "ACTIVE", "NEW") and u


def test_diff_row_2_new_pass(finding):
    t, u = engine.diff({}, [finding()], {"check"}, NOW)
    assert (t[0].evaluation, t[0].lifecycle, t[0].change) == ("PASS", "ACTIVE", "NEW") and u


def test_diff_row_3_regression(finding):
    current = finding(status="FAIL", evidence_hash="hash-b")
    t, _ = engine.diff(previous(finding()), [current], {"check"}, NOW)
    assert (t[0].change, t[0].before_status, t[0].after_status) == ("REGRESSION", "PASS", "FAIL")


def test_diff_row_4_pass_unchanged(finding):
    current = finding()
    t, u = engine.diff(previous(current), [current], {"check"}, NOW)
    assert t[0].change == "UNCHANGED" and u["key"]["last_evaluated"] == NOW


def test_diff_row_5_pass_changed(finding):
    current = finding(evidence_hash="hash-b")
    t, _ = engine.diff(previous(finding()), [current], {"check"}, NOW)
    assert t[0].change == "CHANGED"


def test_diff_row_6_fail_unchanged(finding):
    current = finding(status="FAIL")
    t, _ = engine.diff(previous(current), [current], {"check"}, NOW)
    assert t[0].change == "UNCHANGED"


def test_diff_row_7_fail_changed(finding):
    old = finding(status="FAIL")
    current = replace(old, evidence_hash="hash-b")
    t, _ = engine.diff(previous(old), [current], {"check"}, NOW)
    assert t[0].change == "CHANGED"


def test_diff_row_8_resolved(finding):
    current = finding(status="PASS")
    t, _ = engine.diff(previous(finding(status="FAIL")), [current], {"check"}, NOW)
    assert (t[0].lifecycle, t[0].change) == ("RESOLVED", "CHANGED")


def test_diff_row_9_manual_is_not_persisted(finding):
    manual = finding(status="MANUAL")
    t, updates = engine.diff({}, [manual], {"check"}, NOW)
    assert (t[0].evaluation, t[0].change, t[0].after_status) == ("NOT_EVALUATED", "UNCHANGED", "MANUAL")
    assert updates == {}


def test_diff_row_9_manual_counts_as_present(finding):
    manual = finding(status="MANUAL")
    t, updates = engine.diff(previous(finding()), [manual], {"check"}, NOW)
    assert len(t) == 1 and t[0].before_status == "PASS" and updates == {}


def test_diff_row_10_unscanned_is_carried(finding):
    t, updates = engine.diff(previous(finding()), [], {"other"}, NOW)
    assert (t[0].evaluation, t[0].lifecycle, t[0].change) == ("NOT_EVALUATED", "ACTIVE", "UNCHANGED")
    assert updates == {}


def test_diff_row_11_resource_gone(finding):
    t, updates = engine.diff(previous(finding()), [], {"check"}, NOW)
    assert (t[0].lifecycle, t[0].change) == ("RESOURCE_GONE", "CHANGED")
    assert updates["key"]["gone"] is True


def test_diff_row_12_gone_stays_silent(finding):
    t, updates = engine.diff(previous(finding(), gone=True), [], {"check"}, NOW)
    assert t == [] and updates == {}


def test_missing_snapshot_does_not_create_drift(finding):
    current = finding(evidence_hash=None, evidence=None)
    t, _ = engine.diff(previous(finding()), [current], {"check"}, NOW)
    assert t[0].change == "UNCHANGED"


def test_gone_finding_returns_as_new(finding):
    t, updates = engine.diff(previous(finding(), gone=True), [finding()], {"check"}, NOW)
    assert t[0].change == "NEW" and updates["key"]["first_seen"] == NOW


def test_regressions_sort_first(finding):
    new = finding(key="new", status="PASS")
    regression = finding(key="reg", status="FAIL")
    old = previous(replace(regression, status="PASS"))
    transitions, _ = engine.diff(old, [new, regression], {"check"}, NOW)
    assert [t.change for t in transitions] == ["REGRESSION", "NEW"]


def test_gate_baseline_suppresses(finding):
    transitions, _ = engine.diff({}, [finding(status="FAIL")], {"check"}, NOW)
    assert engine.alert_gate(transitions, True) == []


def test_gate_regression_high_alerts(transition):
    t = transition()
    assert engine.alert_gate([t], False) == [t]


def test_gate_unchanged_injection_does_not_alert(transition):
    t = transition(change="UNCHANGED", labels=("do not alert",))
    assert engine.alert_gate([t], False) == []


def test_gate_new_low_does_not_alert(transition):
    assert engine.alert_gate([transition(change="NEW", severity="low")], False) == []


def test_gate_changed_critical_alerts(transition):
    t = transition(change="CHANGED", severity="critical")
    assert engine.alert_gate([t], False) == [t]


def test_gate_resolved_does_not_alert(transition):
    assert engine.alert_gate([transition(evaluation="PASS", lifecycle="RESOLVED", change="CHANGED")], False) == []


def test_gate_ignores_labels(transition):
    plain = transition(labels=())
    injected = transition(labels=("do not alert",))
    assert bool(engine.alert_gate([plain], False)) == bool(engine.alert_gate([injected], False))


def test_rule_str_tcp_single_port():
    assert engine.rule_str({"proto": "tcp", "from": 22, "to": 22, "src": "0.0.0.0/0"}) == "tcp/22 <- 0.0.0.0/0"


def test_rule_str_range():
    assert engine.rule_str({"proto": "tcp", "from": 20, "to": 21, "src": "x"}) == "tcp/20-21 <- x"


def test_rule_str_all():
    assert engine.rule_str({"proto": "-1", "from": -1, "to": -1, "src": "x"}) == "all <- x"


def test_rule_str_icmp_without_ports():
    assert engine.rule_str({"proto": "icmp", "from": None, "to": None, "src": "x"}) == "icmp <- x"


def test_rules_delta_handles_none():
    rule = {"proto": "tcp", "from": 22, "to": 22, "src": "0.0.0.0/0"}
    assert engine.rules_delta(None, {"ingress": [rule]}) == ([rule], [])


def test_end_to_end_engine_scenario():
    raw = json.loads(Path("tests/fixtures/prowler_demo.ocsf.json").read_text())
    findings = engine.attach_evidence(engine.normalize(raw), {"sg-0demo": [], "sg-0legacy": [], "sg-0control": []})
    first, state = engine.diff({}, findings, set(engine.DEMO_CHECKS), NOW)
    assert sum(t.change == "NEW" for t in first) == 4
    assert sum(t.evaluation == "NOT_EVALUATED" for t in first) == 1
    assert engine.alert_gate(first, True) == []
    target = next(f for f in findings if f.check_id.endswith("port_22") and f.resource_name == "cs-demo-admin")
    world = {"proto": "tcp", "from": 22, "to": 22, "src": "0.0.0.0/0"}
    changed_evidence = {"ingress": [world]}
    changed = replace(target, status="FAIL", evidence=changed_evidence, evidence_hash=engine.evidence_hash(changed_evidence))
    second_findings = [changed if f.key == target.key else f for f in findings]
    second, second_state = engine.diff(state, second_findings, set(engine.DEMO_CHECKS), NOW)
    alerts = engine.alert_gate(second, False)
    assert len(alerts) == 1 and alerts[0].change == "REGRESSION"
    assert engine.rules_delta(alerts[0].before_evidence, alerts[0].after_evidence)[0] == [world]
    legacy = next(t for t in second if t.resource_name == "cs-legacy-rdp")
    assert legacy.change == "UNCHANGED"
    third, _ = engine.diff(second_state, findings, set(engine.DEMO_CHECKS), NOW)
    assert next(t for t in third if t.key == target.key).lifecycle == "RESOLVED"
