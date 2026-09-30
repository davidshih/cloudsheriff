# HANDOFF — daytona-hackathon (CloudSheriff)

Last updated: 2026-09-30 (America/New_York). Branch `main`, pushed to `origin` (public `davidshih/cloudsheriff`).

## Current state
- Docs follow the global `repo-docs` layout since 2026-09-30: `HACKSPRINT_BOUNDARY.md` moved to `docs/reference/hacksprint-boundary.md` (pure rename, `d7e0461`); README links it and gained `## Quick start` and `## Verify`.
- CloudSheriff runs end to end against real AWS. The flow is: read-only STS → an ephemeral Daytona sandbox that runs targeted Prowler (JSON-OCSF) → normalize → three-axis diff → SurrealDB → deterministic alert gate → CloudTrail attribution → LLM explanation traced in Arize → sandbox destroyed.
- Live run verified on 2026-09-30 01:33–01:37Z: baseline (17 NEW) → baseline again (17 UNCHANGED) → `drift.sh open` → scan (1 REGRESSION alert on `cs-demo-admin` tcp/22, attribution to the drift event, LLM explanation) → `drift.sh close` → scan (RESOLVED, 0 alerts). One scan takes about 20–30 s. CloudTrail delivery lag measured at 1.9 min.
- Tests: `uv run pytest -q` gives 70 passed, 1 skipped; with `SURREAL_TEST_URL=ws://127.0.0.1:8000/rpc` it gives 71 passed. `tofu -chdir=terraform test` gives 6 passed.

## Commits
- `09d3e85` import the AWS lab (terraform + scripts)
- `c562628` pipeline (`cloudsheriff/`), tests, plan/review artifacts in `plans/20260928-cloudsheriff-e2e/`
- `529b6f0` live-run fixes: SurrealDB 3.x undefined tables, CloudTrail attribution window, Prowler OCSF name and compliance fields
- `376d06a` `terraform/bootstrap/` for the member account, AWS access docs, `.env.example` restored

## AWS layout (important)
- The management account (id kept out of this public repo) is the user's **Organization management account**, and it is in real use. **Never deploy the lab there.**
- The lab lives in member account `<lab-account-id>` (`cloudsheriff-lab`). It was deployed with `tofu -chdir=terraform apply` (29 resources), and `verify_readonly.sh` passes 20/20.
- Access uses repo-local, gitignored files. `.aws/credentials [cs-mgmt]` holds the management-account IAM user key. `.aws/config [profile cs-sandbox]` assumes `OrganizationAccountAccessRole` in the lab account. `.env` sets `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE` and `AWS_PROFILE=cs-sandbox`. Keep AWS keys out of `.env`: env credentials beat the profile and would hit the management account.
- `CloudSheriffAuditRole` trusts `arn:aws:iam::<lab-account-id>:role/OrganizationAccountAccessRole` with an ExternalId. The id is in `terraform/terraform.tfvars` and `.env` (both gitignored).

## Decisions
- Only Prowler runs inside Daytona. The SG snapshot and CloudTrail lookups run on the orchestrator with the same read-only STS session, which keeps them unit-testable.
- The alert decision is deterministic (`engine.alert_gate`) and never reads labels or text. The LLM only explains alerts that are already decided, and falls back to a template on refusal or error.
- Prowler must run with `--scan-unused-services`; otherwise unattached SGs (`cs-legacy-rdp` bait, `cs-control-private`) are never evaluated.
- The testing phase uses `CS_MODEL=claude-sonnet-5` (in `.env`) at the user's request. The code default is `claude-opus-5-5`.
- SurrealDB writes a whole scan in one transaction and checks afterwards, because on ws a failed transaction does not raise.

## Gotchas
- SurrealDB SDK 2.0: `select(RecordID)` returns a list; `upsert` replaces the whole record. Embedded `mem://` and a 3.x server behave differently for undefined tables.
- Daytona sandbox egress (the user's tier): STS (regional), EC2 and CloudTrail in us-east-1 are reachable. `iam.amazonaws.com` is blocked, so the IAM checks in `--profile cis` will fail.
- `python-dotenv` `load_dotenv()` searches from the calling file's directory. Ad-hoc scripts outside the repo must pass the `.env` path explicitly.
- The harness test-integrity hook flags `skipif`. The server-only test in `tests/test_store.py` is intentional, and the reason is in `529b6f0`.

## TODO (runnable)
1. Security (HIGH): move the orchestrator's source credentials to a least-privilege identity (only `sts:AssumeRole` into the lab admin role, plus `organizations:Describe*`) and keep MFA enforced on human admin users. Details are tracked privately, not in this repo.
2. Bootstrap apply: it needs user approval, and it touches the management account (adds tags, imports into state).
   `set -a; source .env; set +a; tofu -chdir=terraform/bootstrap plan` currently shows 1 import, 1 in-place (tags), 0 destroy.
3. Check the Arize UI: project `cloudsheriff`, trace `cloudsheriff.scan`. Only exporter `force_flush()==True` has been verified.
4. Create a public GitHub repo and push (a hackathon requirement): `gh repo create <name> --public --source . --push`.
5. Evidence per check instead of per SG, so `drift.sh open-rdp` does not re-alert the already-failing port-22 finding as CHANGED.
6. Attribute `ModifySecurityGroupRules` (its requestParameters carry no top-level `groupId`).
7. Rehearse and record a backup video. On the event day, build the declared new feature: agentic investigation and remediation proposals (see `docs/reference/hacksprint-boundary.md`).

## Demo runbook (live)
```bash
surreal start --user root --pass root --bind 127.0.0.1:8000 surrealkv://data/cloudsheriff.db   # separate terminal
set -a; source .env; set +a
uv run python -m cloudsheriff scan --baseline
./scripts/drift.sh open
# wait ~2 min for CloudTrail
uv run python -m cloudsheriff scan
./scripts/drift.sh close && uv run python -m cloudsheriff scan
```

## Not yet verified
- Arize trace contents in the UI.
- `--profile cis` (full CIS 7.0 scan) inside Daytona: IAM endpoint blocked; duration unknown.
- `terraform/bootstrap` apply, and creating a new account from scratch with it.
- Oct-2026 Devpost rules (the page is not published; the rules are inferred from the Nov-2025 and Jan-2026 events).
