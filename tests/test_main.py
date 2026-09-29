from contextlib import contextmanager
from datetime import datetime, timezone

from cloudsheriff import __main__ as main


class Tracer:
    @contextmanager
    def start_as_current_span(self, *args, **kwargs):
        yield object()


def test_enrich_alerts_survives_both_failures(transition, monkeypatch):
    monkeypatch.setattr(main.aws, "cloudtrail_attribution", lambda *args: (_ for _ in ()).throw(RuntimeError("aws")))
    monkeypatch.setattr(main.explain, "explain", lambda *args: (_ for _ in ()).throw(RuntimeError("llm")))
    records = main.enrich_alerts([transition()], object(), "us-east-1", datetime.now(timezone.utc), Tracer())
    assert len(records) == 1
    assert records[0]["attribution"] is None
    assert records[0]["explanation_source"] == "fallback"


def test_enrich_alerts_skips_cloudtrail_for_non_sg_resource(transition, monkeypatch):
    calls = []
    monkeypatch.setattr(main.aws, "cloudtrail_attribution", lambda *args: calls.append(args) or {"actor": "wrong"})
    monkeypatch.setattr(main.explain, "explain", lambda *args: ("text", "model"))
    alert = transition(resource_uid="arn:aws:iam::111122223333:root")
    record = main.enrich_alerts([alert], object(), "us-east-1", datetime.now(timezone.utc), Tracer())[0]
    assert calls == []
    assert record["attribution"] is None


def test_enrich_alerts_success(transition, monkeypatch):
    attribution = {"actor": "actor"}
    monkeypatch.setattr(main.aws, "cloudtrail_attribution", lambda *args: attribution)
    monkeypatch.setattr(main.explain, "explain", lambda *args: ("text", "model"))
    record = main.enrich_alerts([transition()], object(), "us-east-1", datetime.now(timezone.utc), Tracer())[0]
    assert record["attribution"] == attribution and record["explanation"] == "text"
