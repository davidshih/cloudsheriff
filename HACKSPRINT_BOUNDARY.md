# CloudSheriff HackSprint build boundary

## Rules as currently known

The Daytona HackSprint NYC Nov-2025 and SF Jan-2026 Devpost rules state: "Projects may build upon existing work, but teams must create at least one completely new feature during the hackathon and clearly specify which feature was developed at the event." A public GitHub repository and video demo are also required. The Oct-2026 Devpost page is not published yet, so these rules must be re-checked when it appears.

## Built before the event

- The Terraform/OpenTofu AWS lab with known PASS, FAIL, prompt-injection-bait, negative-control, and manually driftable resources
- Read-only STS role assumption with ExternalId
- Daytona snapshot build and ephemeral Prowler scan room
- JSON-OCSF normalization and canonical security-group snapshots
- Three-axis state/diff engine and SurrealDB persistence
- Deterministic alert gate
- CloudTrail attribution
- Claude explanation with deterministic fallback and Arize tracing
- CLI orchestration and offline tests

## Built at the event

To be declared on 16 Oct 2026. Candidate: agentic investigation and remediation proposals under read-only credentials, with the deterministic alert gate unchanged.

## Demo contract

Baseline exists before the live demo. During the demo:

1. Manually open `tcp/22` on `cs-demo-admin` to `0.0.0.0/0` using admin credentials.
2. Start a targeted scan with `--scan-unused-services` in a fresh Daytona sandbox using short-lived read-only STS credentials.
3. Detect a CIS regression with Prowler.
4. Compare the current canonical SG snapshot with the saved baseline.
5. Attribute the change using CloudTrail Event History.
6. Apply deterministic alert policy.
7. Ask the LLM only to explain the already-decided alert; trace that call in Arize.
8. Destroy the scan sandbox.

The LLM never decides whether an alert exists and never receives an AWS write-capable credential.
