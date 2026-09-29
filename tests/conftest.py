from dataclasses import replace

import pytest

from cloudsheriff.engine import Finding, Transition


@pytest.fixture
def finding():
    def make(**changes):
        base = Finding(
            key="key", check_id="check", status="PASS", severity="high", title="title",
            resource_uid="arn:aws:ec2:us-east-1:111122223333:security-group/sg-1",
            resource_name="group", resource_type="AwsEc2SecurityGroup", region="us-east-1",
            account="111122223333", labels=("Name:group",), compliance={"CIS-7.0": ["5.3"]},
            evidence={"ingress": []}, evidence_hash="hash-a",
        )
        return replace(base, **changes)
    return make


@pytest.fixture
def transition():
    def make(**changes):
        base = Transition(
            key="key", check_id="check", title="title", severity="high",
            resource_uid="arn:aws:ec2:us-east-1:111122223333:security-group/sg-1",
            resource_name="group", region="us-east-1", account="111122223333",
            evaluation="FAIL", lifecycle="ACTIVE", change="REGRESSION", before_status="PASS",
            after_status="FAIL", before_evidence={"ingress": []},
            after_evidence={"ingress": [{"proto": "tcp", "from": 22, "to": 22, "src": "0.0.0.0/0"}]},
            labels=("Name:group",), compliance={"CIS-7.0": ["5.3"]},
        )
        return replace(base, **changes)
    return make
