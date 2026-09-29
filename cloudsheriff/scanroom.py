from __future__ import annotations

import json

from daytona import (
    CreateSandboxFromSnapshotParams,
    CreateSnapshotParams,
    Daytona,
    DaytonaNotFoundError,
    Image,
)


PROWLER_VERSION = "5.43.0"
SNAPSHOT_NAME = "cloudsheriff-prowler-5-43-0"
OUT_DIR = "/tmp/cs-out"


def build_image() -> None:
    daytona = Daytona()
    try:
        snapshot = daytona.snapshot.get(SNAPSHOT_NAME)
        print(f"snapshot {SNAPSHOT_NAME} already exists ({snapshot.state})")
        return
    except DaytonaNotFoundError:
        pass
    image = Image.debian_slim("3.12").pip_install(f"prowler=={PROWLER_VERSION}")
    daytona.snapshot.create(CreateSnapshotParams(name=SNAPSHOT_NAME, image=image), on_logs=print)


def prowler_command(region: str, checks: list[str] | None, compliance: str | None) -> str:
    if bool(checks) == bool(compliance):
        raise ValueError("exactly one of checks or compliance is required")
    selector = f"--checks {' '.join(checks)}" if checks else f"--compliance {compliance}"
    return (
        f"prowler aws {selector} --region {region} --scan-unused-services "
        f"-M json-ocsf -o {OUT_DIR} -F scan -z -b --no-color"
    )


def run_prowler(
    creds_env: dict[str, str],
    region: str,
    checks: list[str] | None,
    compliance: str | None,
    timeout_s: int,
    daytona=None,
) -> tuple[list[dict], str]:
    client = daytona or Daytona()
    snapshot = client.snapshot.get(SNAPSHOT_NAME)
    if getattr(snapshot.state, "value", snapshot.state) == "inactive":
        client.snapshot.activate(SNAPSHOT_NAME)
    sandbox = client.create(
        CreateSandboxFromSnapshotParams(
            snapshot=SNAPSHOT_NAME,
            ephemeral=True,
            labels={"app": "cloudsheriff"},
        ),
        timeout=180,
    )
    try:
        response = sandbox.process.exec(
            prowler_command(region, checks, compliance), env=creds_env, timeout=timeout_s
        )
        if response.exit_code != 0:
            raise RuntimeError(f"Prowler failed: {response.result[-2000:]}")
        data = sandbox.fs.download_file(f"{OUT_DIR}/scan.ocsf.json")
        return json.loads(data), sandbox.id
    finally:
        try:
            client.delete(sandbox, wait=True)
            print(f"sandbox {sandbox.id} destroyed")
        except Exception:
            print(f"warning: failed to destroy sandbox {sandbox.id}")
