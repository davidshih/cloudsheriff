from __future__ import annotations

import json
from datetime import datetime, timezone

import boto3


def assume_audit_role(
    role_arn: str, external_id: str, region: str, duration_seconds: int
) -> tuple[dict[str, str], boto3.Session]:
    base = boto3.Session(region_name=region)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    response = base.client("sts").assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"cloudsheriff-{timestamp}",
        ExternalId=external_id,
        DurationSeconds=duration_seconds,
    )
    credentials = response["Credentials"]
    env = {
        "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"],
        "AWS_SESSION_TOKEN": credentials["SessionToken"],
        "AWS_DEFAULT_REGION": region,
        "AWS_REGION": region,
        "AWS_STS_REGIONAL_ENDPOINTS": "regional",
    }
    session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )
    return env, session


def sg_rules_by_id(session, region: str, sg_ids: list[str]) -> dict[str, list[dict]]:
    if not sg_ids:
        return {}
    grouped: dict[str, list[dict]] = {sg_id: [] for sg_id in sg_ids}
    paginator = session.client("ec2", region_name=region).get_paginator("describe_security_group_rules")
    for page in paginator.paginate(Filters=[{"Name": "group-id", "Values": sg_ids}]):
        for rule in page.get("SecurityGroupRules", []):
            grouped.setdefault(rule["GroupId"], []).append(rule)
    return grouped


def cloudtrail_attribution(session, region: str, sg_id: str, since: datetime) -> dict | None:
    client = session.client("cloudtrail", region_name=region)
    matches = []
    end = datetime.now(timezone.utc)
    for name in (
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "ModifySecurityGroupRules",
    ):
        paginator = client.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
            StartTime=since,
            EndTime=end,
        ):
            for wrapper in page.get("Events", []):
                event = json.loads(wrapper["CloudTrailEvent"])
                if (event.get("requestParameters") or {}).get("groupId") != sg_id:
                    continue
                identity = event.get("userIdentity") or {}
                issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
                event_time = event.get("eventTime") or wrapper.get("EventTime")
                if isinstance(event_time, datetime):
                    event_time = event_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                matches.append((event_time or "", {
                    "actor": identity.get("arn") or issuer.get("arn") or "unknown",
                    "event_name": event.get("eventName") or name,
                    "event_time": event_time,
                    "source_ip": event.get("sourceIPAddress"),
                }))
    # CloudTrail usually lags about five minutes; None means attribution is pending, not "nobody".
    return max(matches, key=lambda item: item[0])[1] if matches else None
