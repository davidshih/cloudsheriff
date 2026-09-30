from __future__ import annotations

from dataclasses import asdict

from surrealdb import RecordID, Surreal

from .engine import Transition


NS, DB = "cloudsheriff", "lab"


class Store:
    def __init__(self, url: str, user: str | None = None, password: str | None = None):
        self.url = url
        self.user = user
        self.password = password
        self.connection = None
        self.db = None

    def __enter__(self):
        self.connection = Surreal(self.url)
        self.db = self.connection.__enter__()
        if self.url.startswith(("ws", "http")):
            self.db.signin({"username": self.user, "password": self.password})
        self.db.use(NS, DB)
        # SurrealDB 3.x servers reject SELECT on a table that does not exist yet.
        self.db.query(
            "DEFINE TABLE IF NOT EXISTS finding SCHEMALESS;"
            "DEFINE TABLE IF NOT EXISTS scan SCHEMALESS;"
            "DEFINE TABLE IF NOT EXISTS event SCHEMALESS;"
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self.connection.__exit__(exc_type, exc_value, traceback)

    @staticmethod
    def _without_id(record: dict) -> dict:
        return {key: value for key, value in record.items() if key != "id"}

    def load_state(self) -> dict[str, dict]:
        records = self.db.select("finding") or []
        return {record["key"]: self._without_id(record) for record in records}

    def last_scan(self) -> dict | None:
        records = self.db.query("SELECT * FROM scan ORDER BY finished_at DESC LIMIT 1") or []
        return self._without_id(records[0]) if records else None

    def save_scan(
        self,
        scan: dict,
        transitions: list[Transition],
        updates: dict[str, dict],
        alerts: list[dict],
    ) -> None:
        statements = ["BEGIN TRANSACTION;"]
        variables = {}
        for index, (key, data) in enumerate(updates.items()):
            statements.append(f"UPSERT $f{index} CONTENT $d{index};")
            variables[f"f{index}"] = RecordID("finding", key)
            variables[f"d{index}"] = data
        variables["scan_id"] = RecordID("scan", scan["scan_id"])
        variables["scan"] = scan
        statements.append("CREATE $scan_id CONTENT $scan;")
        alert_by_key = {alert["key"]: alert for alert in alerts}
        event_index = 0
        for transition in transitions:
            alert = alert_by_key.get(transition.key)
            if transition.change == "UNCHANGED" and alert is None:
                continue
            event = {
                **asdict(transition),
                "labels": list(transition.labels),
                "scan_id": scan["scan_id"],
                "alert": alert is not None,
                "attribution": None,
                "explanation": None,
                "explanation_source": None,
            }
            if alert:
                event.update({key: value for key, value in alert.items() if key != "key"})
            statements.append(f"CREATE $e{event_index} CONTENT $v{event_index};")
            variables[f"e{event_index}"] = RecordID("event", f"{scan['scan_id']}_{transition.key}")
            variables[f"v{event_index}"] = event
            event_index += 1
        statements.append("COMMIT TRANSACTION;")
        self.db.query("\n".join(statements), variables)
        if not self.db.select(RecordID("scan", scan["scan_id"])):
            raise RuntimeError("scan not persisted; transaction rolled back")
