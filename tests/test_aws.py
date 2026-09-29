import json
from datetime import datetime, timezone
from enum import Enum
from types import SimpleNamespace

import pytest

from cloudsheriff import aws, scanroom


class Paginator:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def paginate(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages


class Client:
    def __init__(self, pages):
        self.paginator = Paginator(pages)

    def get_paginator(self, name):
        return self.paginator


class Session:
    def __init__(self, clients):
        self.clients = clients

    def client(self, name, **kwargs):
        return self.clients[name]


def test_sg_rules_empty_avoids_client():
    assert aws.sg_rules_by_id(None, "us-east-1", []) == {}


def test_sg_rules_groups_and_includes_empty_ids():
    client = Client([{"SecurityGroupRules": [{"GroupId": "sg-a", "x": 1}, {"GroupId": "sg-a", "x": 2}]}])
    result = aws.sg_rules_by_id(Session({"ec2": client}), "us-east-1", ["sg-a", "sg-b"])
    assert [r["x"] for r in result["sg-a"]] == [1, 2]
    assert result["sg-b"] == []


def cloudtrail_wrapper(group, time, *, arn=None, issuer=None, name="AuthorizeSecurityGroupIngress"):
    identity = {"arn": arn, "sessionContext": {"sessionIssuer": {"arn": issuer}}}
    event = {"requestParameters": {"groupId": group}, "userIdentity": identity, "eventName": name, "eventTime": time, "sourceIPAddress": "1.2.3.4"}
    return {"CloudTrailEvent": json.dumps(event)}


def test_cloudtrail_filters_group_and_picks_latest():
    pages = [{"Events": [cloudtrail_wrapper("sg-x", "2026-01-01T00:00:00Z", arn="wrong"), cloudtrail_wrapper("sg-a", "2026-01-01T00:00:00Z", arn="old"), cloudtrail_wrapper("sg-a", "2026-01-02T00:00:00Z", arn="new")]}]
    result = aws.cloudtrail_attribution(Session({"cloudtrail": Client(pages)}), "us-east-1", "sg-a", datetime.now(timezone.utc))
    assert result["actor"] == "new" and result["event_time"] == "2026-01-02T00:00:00Z"


def test_cloudtrail_falls_back_to_session_issuer():
    pages = [{"Events": [cloudtrail_wrapper("sg-a", "2026-01-01T00:00:00Z", issuer="issuer")]}]
    result = aws.cloudtrail_attribution(Session({"cloudtrail": Client(pages)}), "us-east-1", "sg-a", datetime.now(timezone.utc))
    assert result["actor"] == "issuer"


def test_cloudtrail_returns_none_without_match():
    session = Session({"cloudtrail": Client([{"Events": []}])})
    assert aws.cloudtrail_attribution(session, "us-east-1", "sg-a", datetime.now(timezone.utc)) is None


def test_prowler_command_checks():
    command = scanroom.prowler_command("us-east-1", ["a", "b"], None)
    assert "--checks a b" in command and "--scan-unused-services" in command
    assert "-M json-ocsf" in command and " -z " in command


def test_prowler_command_compliance():
    assert "--compliance cis_7.0_aws" in scanroom.prowler_command("us-east-1", None, "cis_7.0_aws")


def test_prowler_command_rejects_both_or_neither():
    with pytest.raises(ValueError):
        scanroom.prowler_command("us-east-1", ["a"], "cis")
    with pytest.raises(ValueError):
        scanroom.prowler_command("us-east-1", None, None)


class Process:
    def __init__(self, response):
        self.response = response

    def exec(self, *args, **kwargs):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class FS:
    def __init__(self, data):
        self.data = data

    def download_file(self, path):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data


class Snapshot:
    def __init__(self, state):
        self.state = state


class SnapshotAPI:
    def __init__(self, state):
        self.state = state
        self.activated = []

    def get(self, name):
        return Snapshot(self.state)

    def activate(self, name):
        self.activated.append(name)


class FakeDaytona:
    def __init__(self, *, exit_code=0, result="", data='[{"ok": true}]', state="active", delete_error=None):
        self.snapshot = SnapshotAPI(state)
        self.sandbox = SimpleNamespace(id="sandbox-1", process=Process(SimpleNamespace(exit_code=exit_code, result=result)), fs=FS(data))
        self.deleted = []
        self.delete_error = delete_error

    def create(self, params, timeout):
        return self.sandbox

    def delete(self, sandbox, wait=False):
        self.deleted.append((sandbox.id, wait))
        if self.delete_error:
            raise self.delete_error


def run(fake):
    return scanroom.run_prowler({}, "us-east-1", ["check"], None, 10, daytona=fake)


def test_run_prowler_success_and_waits_for_delete():
    fake = FakeDaytona()
    assert run(fake) == ([{"ok": True}], "sandbox-1")
    assert fake.deleted == [("sandbox-1", True)]


def test_run_prowler_nonzero_raises_and_deletes():
    fake = FakeDaytona(exit_code=3, result="failed")
    with pytest.raises(RuntimeError, match="failed"):
        run(fake)
    assert fake.deleted == [("sandbox-1", True)]


def test_run_prowler_download_error_propagates_and_deletes():
    fake = FakeDaytona(data=OSError("download"))
    with pytest.raises(OSError, match="download"):
        run(fake)
    assert fake.deleted


def test_run_prowler_invalid_json_deletes():
    fake = FakeDaytona(data="not json")
    with pytest.raises(json.JSONDecodeError):
        run(fake)
    assert fake.deleted


def test_run_prowler_delete_does_not_mask_original():
    fake = FakeDaytona(exit_code=3, result="original", delete_error=OSError("delete"))
    with pytest.raises(RuntimeError, match="original"):
        run(fake)


def test_run_prowler_activates_inactive_enum():
    class State(str, Enum):
        INACTIVE = "inactive"
        ACTIVE = "active"
    inactive = FakeDaytona(state=State.INACTIVE)
    active = FakeDaytona(state=State.ACTIVE)
    run(inactive)
    run(active)
    assert inactive.snapshot.activated == [scanroom.SNAPSHOT_NAME]
    assert active.snapshot.activated == []
