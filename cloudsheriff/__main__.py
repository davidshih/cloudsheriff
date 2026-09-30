from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from opentelemetry import trace

load_dotenv()

from . import aws, engine, explain, scanroom  # noqa: E402
from .store import Store  # noqa: E402


REQUIRED_ENV = ("CS_AUDIT_ROLE_ARN", "CS_AUDIT_EXTERNAL_ID", "DAYTONA_API_KEY", "SURREAL_URL")


def now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now().strftime("%Y-%m-%dT%H:%M:%SZ")


def attribution_since(last: dict | None) -> datetime:
    # Changes before the previous scan finished are already part of its baseline.
    if last:
        return datetime.fromisoformat(last["finished_at"].replace("Z", "+00:00"))
    return now() - timedelta(hours=24)


def enrich_alerts(alerts, audit, region, since, tracer) -> list[dict]:
    records = []
    for transition in alerts:
        attribution = None
        sg_id = engine.sg_id_from_uid(transition.resource_uid)
        try:
            if sg_id:  # CloudTrail attribution only covers security-group changes
                with tracer.start_as_current_span(
                    "cloudtrail.attribution", attributes={"openinference.span.kind": "TOOL"}
                ):
                    attribution = aws.cloudtrail_attribution(audit, region, sg_id, since)
        except Exception as exc:
            print(f"warning: CloudTrail attribution failed ({type(exc).__name__})")
        try:
            text, source = explain.explain(transition, attribution)
        except Exception as exc:
            print(f"warning: explanation wrapper failed ({type(exc).__name__})")
            text, source = explain.fallback_text(transition, attribution), "fallback"
        records.append({
            "key": transition.key,
            "attribution": attribution,
            "explanation": text,
            "explanation_source": source,
        })
    return records


def print_report(scan: dict, transitions, alert_records: list[dict]) -> None:
    counts = scan["counts"]
    print(
        f"scan {scan['scan_id']} [{scan['profile']}] findings={len(transitions)}  "
        f"REGRESSION={counts.get('REGRESSION', 0)} NEW={counts.get('NEW', 0)} "
        f"CHANGED={counts.get('CHANGED', 0)} UNCHANGED={counts.get('UNCHANGED', 0)} "
        f"RESOURCE_GONE={sum(t.lifecycle == 'RESOURCE_GONE' for t in transitions)}  "
        f"alerts={scan['alert_count']}  sandbox {scan['sandbox_id']} destroyed"
    )
    by_key = {record["key"]: record for record in alert_records}
    for transition in transitions:
        record = by_key.get(transition.key)
        if not record:
            continue
        print(f"\n=== ALERT  {transition.severity.upper()}  {transition.change} ===")
        print(f"check     {transition.check_id}   {transition.compliance}")
        sg_id = engine.sg_id_from_uid(transition.resource_uid)
        print(f"resource  {sg_id} ({transition.resource_name})  {transition.region}")
        added, _ = engine.rules_delta(transition.before_evidence, transition.after_evidence)
        for heading, evidence in (("BEFORE", transition.before_evidence), ("AFTER", transition.after_evidence)):
            rules = (evidence or {}).get("ingress", [])
            rendered = []
            for rule in rules:
                suffix = "   (+)" if heading == "AFTER" and rule in added else ""
                rendered.append(engine.rule_str(rule) + suffix)
            print(f"{heading:<10}" + ("\n          ".join(rendered) or "none"))
        attribution = record["attribution"]
        if attribution:
            print(
                f"changed   {attribution['actor']}   {attribution['event_name']}   "
                f"{attribution['event_time']}   from {attribution.get('source_ip')}"
            )
        else:
            print("changed   attribution pending — CloudTrail delivery usually lags ~5 min")
        print(f"explain   [{record['explanation_source']}]\n          {record['explanation']}")
    noise = [t for t in transitions if t.evaluation == "FAIL" and t.change == "UNCHANGED" and t.key not in by_key]
    if noise:
        names = ", ".join(sorted({t.resource_name for t in noise}))
        print(f"known noise (no alert): {len(noise)} findings on {names}")


def run_scan(args) -> int:
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        print("missing required environment variables: " + ", ".join(missing))
        return 2
    region = os.environ.get("AWS_REGION", "us-east-1")
    provider = explain.setup_tracing()
    tracer = (provider or trace).get_tracer("cloudsheriff")
    checks, compliance, duration = (
        (engine.DEMO_CHECKS, None, 900) if args.profile == "demo" else (None, "cis_7.0_aws", 3600)
    )
    with tracer.start_as_current_span(
        "cloudsheriff.scan",
        attributes={
            "openinference.span.kind": "CHAIN",
            "scan.profile": args.profile,
            "scan.baseline": args.baseline,
        },
    ) as root:
        started = now_iso()
        scan_id = now().strftime("%Y%m%dT%H%M%SZ")
        creds_env, audit = aws.assume_audit_role(
            os.environ["CS_AUDIT_ROLE_ARN"], os.environ["CS_AUDIT_EXTERNAL_ID"], region, duration
        )
        with tracer.start_as_current_span(
            "scanroom.prowler", attributes={"openinference.span.kind": "TOOL"}
        ):
            ocsf, sandbox_id = scanroom.run_prowler(creds_env, region, checks, compliance, duration)
        findings = engine.normalize(ocsf)
        sg_ids = sorted(filter(None, {engine.sg_id_from_uid(f.resource_uid) for f in findings}))
        findings = engine.attach_evidence(findings, aws.sg_rules_by_id(audit, region, sg_ids))
        scanned = set(checks) if checks else {finding.check_id for finding in findings}
        with Store(
            os.environ["SURREAL_URL"], os.environ.get("SURREAL_USER"), os.environ.get("SURREAL_PASS")
        ) as store:
            previous, last = store.load_state(), store.last_scan()
            transitions, updates = engine.diff(previous, findings, scanned, now_iso())
            alerts = engine.alert_gate(transitions, args.baseline)
            alert_records = enrich_alerts(alerts, audit, region, attribution_since(last), tracer)
            counts = dict(Counter(transition.change for transition in transitions))
            scan = {
                "scan_id": scan_id,
                "started_at": started,
                "finished_at": now_iso(),
                "profile": args.profile,
                "baseline": args.baseline,
                "region": region,
                "account": findings[0].account if findings else "",
                "sandbox_id": sandbox_id,
                "scanned_checks": sorted(scanned),
                "counts": counts,
                "alert_count": len(alerts),
            }
            store.save_scan(scan, transitions, updates, alert_records)
        root.set_attribute("output.value", json.dumps({"alerts": len(alerts), "counts": counts}))
    print_report(scan, transitions, alert_records)
    if provider:
        provider.force_flush()
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="cloudsheriff")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("build-image", help="build the Daytona Prowler snapshot")
    scan = commands.add_parser("scan", help="run a CloudSheriff scan")
    scan.add_argument("--baseline", action="store_true", help="record state and suppress alerts")
    scan.add_argument("--profile", choices=("demo", "cis"), default="demo")
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "build-image":
        scanroom.build_image()
        return 0
    return run_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
