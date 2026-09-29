# CloudSheriff HackSprint build boundary

This lab is pre-event test material. It intentionally stops before implementing the core CloudSheriff product.

## Safe to prepare before the event

- Terraform/OpenTofu fixture in this repository
- Known PASS / FAIL / prompt-injection-bait resources
- `drift.sh` manual configuration changes
- Read-only IAM-role proof
- Daytona hello-world / image build proof
- Prowler hello-world and sample JSON-OCSF files
- SurrealDB connection hello-world
- Arize tracing hello-world
- Unit-test fixtures and expected state-machine cases

## Core to build during the event

1. Prowler JSON-OCSF normalizer
2. Canonical AWS resource snapshotter for the demo resource(s)
3. Stable finding identity + structured evidence hash
4. State/diff engine
   - PASS / FAIL / NOT_EVALUATED
   - ACTIVE / RESOLVED / RESOURCE_GONE
   - NEW / REGRESSION / CHANGED / UNCHANGED
5. SurrealDB persistence and previous-scan lookup
6. Deterministic alert gate
7. CloudTrail attribution join (who / when / API)
8. AI-only explanation layer with Arize tracing
9. Daytona ephemeral scan-room orchestration

## Demo contract

Baseline exists before the live demo. During the demo:

1. Manually open `tcp/22` on `cs-demo-admin` to `0.0.0.0/0` using admin credentials.
2. Start a targeted scan in a fresh Daytona sandbox with short-lived read-only STS credentials.
3. Detect a CIS regression with Prowler.
4. Compare the current canonical SG snapshot with the saved baseline.
5. Attribute the change using CloudTrail Event History.
6. Apply deterministic alert policy.
7. Ask the LLM only to explain the already-decided alert; trace that call in Arize.
8. Destroy the scan sandbox.

The LLM never decides whether an alert exists and never receives an AWS write-capable credential.
