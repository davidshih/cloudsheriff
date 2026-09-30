from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Any


DEMO_CHECKS = [
    "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
    "ec2_securitygroup_default_restrict_traffic",
]
CIS_FRAMEWORK = "CIS-7.0"
ALERT_SEVERITIES = {"critical", "high", "medium"}
ALERT_CHANGES = {"NEW", "REGRESSION", "CHANGED"}


@dataclass(frozen=True)
class Finding:
    key: str
    check_id: str
    status: str
    severity: str
    title: str
    resource_uid: str
    resource_name: str
    resource_type: str
    region: str
    account: str
    labels: tuple[str, ...]
    compliance: dict[str, list[str]]
    evidence: dict[str, Any] | None = None
    evidence_hash: str | None = None


@dataclass(frozen=True)
class Transition:
    key: str
    check_id: str
    title: str
    severity: str
    resource_uid: str
    resource_name: str
    region: str
    account: str
    evaluation: str
    lifecycle: str
    change: str
    before_status: str | None
    after_status: str | None
    before_evidence: dict[str, Any] | None
    after_evidence: dict[str, Any] | None
    labels: tuple[str, ...]
    compliance: dict[str, list[str]]


def finding_key(account: str, region: str, check_id: str, resource_uid: str) -> str:
    raw = "|".join((account, region, check_id, resource_uid)).encode()
    return hashlib.sha256(raw).hexdigest()[:24]


def normalize(ocsf: list[dict]) -> list[Finding]:
    findings = []
    for item in ocsf:
        resources = item.get("resources") or []
        if not resources:
            continue
        resource = resources[0]
        account = ((item.get("cloud") or {}).get("account") or {}).get("uid", "")
        region = resource.get("region", "")
        check_id = (item.get("metadata") or {}).get("event_code", "")
        uid = resource.get("uid", "")
        compliance = {
            key: value
            for key, value in ((item.get("unmapped") or {}).get("compliance") or {}).items()
            if key == CIS_FRAMEWORK
        }
        # Prowler puts the SG id in resources[0].name; the real name is the structured data.metadata.name.
        metadata = (resource.get("data") or {}).get("metadata") or {}
        name = metadata.get("name") if isinstance(metadata, dict) else None
        findings.append(
            Finding(
                key=finding_key(account, region, check_id, uid),
                check_id=check_id,
                status=item.get("status_code", ""),
                severity=str(item.get("severity", "")).lower(),
                title=(item.get("finding_info") or {}).get("title", ""),
                resource_uid=uid,
                resource_name=name or resource.get("name", ""),
                resource_type=resource.get("type", ""),
                region=region,
                account=account,
                labels=tuple(resource.get("labels") or []),
                compliance=compliance,
            )
        )
    return findings


def sg_id_from_uid(resource_uid: str) -> str | None:
    marker = ":security-group/"
    return resource_uid.split(marker, 1)[1] if marker in resource_uid else None


def canonical_sg_rules(rules: list[dict]) -> list[dict]:
    canonical = {}
    for rule in rules:
        if rule.get("IsEgress") is not False:
            continue
        source = rule.get("CidrIpv4") or rule.get("CidrIpv6")
        if not source and (ref := rule.get("ReferencedGroupInfo")):
            source = f"sg:{ref.get('GroupId')}"
        if not source and rule.get("PrefixListId"):
            source = f"pl:{rule['PrefixListId']}"
        value = {
            "proto": rule.get("IpProtocol"),
            "from": rule.get("FromPort"),
            "to": rule.get("ToPort"),
            "src": source,
        }
        canonical[(value["proto"], value["from"], value["to"], value["src"])] = value

    def sort_key(rule: dict) -> tuple:
        return (
            rule["proto"],
            -2 if rule["from"] is None else rule["from"],
            -2 if rule["to"] is None else rule["to"],
            rule["src"] or "",
        )

    return sorted(canonical.values(), key=sort_key)


def evidence_hash(evidence: dict) -> str:
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def attach_evidence(findings: list[Finding], sg_rules_by_id: dict[str, list[dict]]) -> list[Finding]:
    result = []
    for finding in findings:
        sg_id = sg_id_from_uid(finding.resource_uid)
        if sg_id in sg_rules_by_id:
            evidence = {"ingress": canonical_sg_rules(sg_rules_by_id[sg_id])}
            finding = replace(finding, evidence=evidence, evidence_hash=evidence_hash(evidence))
        result.append(finding)
    return result


def _hash_changed(before: str | None, after: str | None) -> bool:
    return before is not None and after is not None and before != after


def _transition(
    data: Finding | dict,
    evaluation: str,
    lifecycle: str,
    change: str,
    before_status: str | None,
    after_status: str | None,
    before_evidence: dict | None,
    after_evidence: dict | None,
) -> Transition:
    get = (lambda key: getattr(data, key)) if isinstance(data, Finding) else data.get
    return Transition(
        key=get("key"), check_id=get("check_id"), title=get("title"), severity=get("severity"),
        resource_uid=get("resource_uid"), resource_name=get("resource_name"), region=get("region"),
        account=get("account"), evaluation=evaluation, lifecycle=lifecycle, change=change,
        before_status=before_status, after_status=after_status, before_evidence=before_evidence,
        after_evidence=after_evidence, labels=tuple(get("labels") or []), compliance=get("compliance") or {},
    )


def _state_record(finding: Finding, previous: dict | None, now: str) -> dict:
    return {
        "key": finding.key, "check_id": finding.check_id, "title": finding.title,
        "severity": finding.severity, "resource_uid": finding.resource_uid,
        "resource_name": finding.resource_name, "region": finding.region, "account": finding.account,
        "labels": list(finding.labels), "compliance": finding.compliance,
        "last_status": finding.status, "evidence": finding.evidence,
        "evidence_hash": finding.evidence_hash,
        "first_seen": previous.get("first_seen", now) if previous else now,
        "last_evaluated": now, "gone": False,
    }


def diff(
    prev: dict[str, dict], findings: list[Finding], scanned_checks: set[str], now: str
) -> tuple[list[Transition], dict[str, dict]]:
    transitions: list[Transition] = []
    updates: dict[str, dict] = {}
    present = {finding.key for finding in findings}
    for finding in findings:
        previous = prev.get(finding.key)
        if finding.status == "MANUAL":
            transitions.append(_transition(
                finding, "NOT_EVALUATED", "ACTIVE", "UNCHANGED",
                previous.get("last_status") if previous else None, "MANUAL",
                previous.get("evidence") if previous else None, finding.evidence,
            ))
            continue
        usable_previous = previous if previous and not previous.get("gone") else None
        before_status = usable_previous.get("last_status") if usable_previous else None
        before_evidence = usable_previous.get("evidence") if usable_previous else None
        if usable_previous is None:
            lifecycle, change = "ACTIVE", "NEW"
        elif before_status == "PASS" and finding.status == "FAIL":
            lifecycle, change = "ACTIVE", "REGRESSION"
        elif before_status == "FAIL" and finding.status == "PASS":
            lifecycle, change = "RESOLVED", "CHANGED"
        else:
            lifecycle = "ACTIVE"
            change = "CHANGED" if _hash_changed(usable_previous.get("evidence_hash"), finding.evidence_hash) else "UNCHANGED"
        transitions.append(_transition(
            finding, finding.status, lifecycle, change, before_status, finding.status,
            before_evidence, finding.evidence,
        ))
        updates[finding.key] = _state_record(finding, usable_previous, now)

    for key, previous in prev.items():
        if key in present or previous.get("gone"):
            continue
        if previous["check_id"] not in scanned_checks:
            transitions.append(_transition(
                previous, "NOT_EVALUATED", "ACTIVE", "UNCHANGED", previous.get("last_status"), None,
                previous.get("evidence"), None,
            ))
            continue
        transitions.append(_transition(
            previous, "NOT_EVALUATED", "RESOURCE_GONE", "CHANGED", previous.get("last_status"), None,
            previous.get("evidence"), None,
        ))
        updates[key] = {**previous, "gone": True, "last_evaluated": now}

    transitions.sort(key=lambda t: (t.change != "REGRESSION", t.change, t.key))
    return transitions, updates


def alert_gate(transitions: list[Transition], baseline: bool) -> list[Transition]:
    # Safeguard: alerting depends only on structured policy fields, never untrusted text.
    if baseline:
        return []
    return [
        transition for transition in transitions
        if transition.evaluation == "FAIL"
        and transition.change in ALERT_CHANGES
        and transition.severity in ALERT_SEVERITIES
    ]


def rule_str(rule: dict) -> str:
    protocol = "all" if rule.get("proto") == "-1" else str(rule.get("proto"))
    start, end = rule.get("from"), rule.get("to")
    port = ""
    if start not in (None, -1):
        port = f"/{start}" if start == end else f"/{start}-{end}"
    return f"{protocol}{port} <- {rule.get('src')}"


def rules_delta(before_evidence: dict | None, after_evidence: dict | None) -> tuple[list[dict], list[dict]]:
    before = (before_evidence or {}).get("ingress", [])
    after = (after_evidence or {}).get("ingress", [])
    encode = lambda rule: json.dumps(rule, sort_keys=True)
    before_map, after_map = ({encode(r): r for r in before}, {encode(r): r for r in after})
    return (
        [after_map[key] for key in sorted(after_map.keys() - before_map.keys())],
        [before_map[key] for key in sorted(before_map.keys() - after_map.keys())],
    )
