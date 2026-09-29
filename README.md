# CloudSheriff Lab: intentionally misconfigured AWS test environment

A lab environment for demoing and testing CloudSheriff (read-only CIS drift monitor).

> **Scope:** this repository is intentionally only the AWS test fixture. It creates known-good, known-bad, and manually driftable resources. The CloudSheriff core (normalizer, state/diff engine, SurrealDB persistence, Daytona scan-room orchestration, deterministic alert gate, and AI explanation pipeline) is deliberately **not** implemented here, so the core functionality can be built during the HackSprint.
**Deploy it only in a dedicated sandbox AWS account.** Two guards prevent mistakes:

1. The provider sets `allowed_account_ids`, so it refuses to run against any other account.
2. You must explicitly set `i_understand_this_is_insecure = true`, otherwise `plan` fails immediately.

## What it deploys

| Resource | State | Expected CIS 7.0 result | Role in the demo |
|---|---|---|---|
| `cs-demo-admin` SG | SSH only from `10.10.0.0/16` | **PASS** (baseline) | ★ Drift target: `drift.sh open` → REGRESSION |
| `production-web-01` (t4g.nano, **stopped**) | IMDSv1, root volume unencrypted, attached to demo SG | FAIL (IMDSv2, EBS) | Gives the AI "production workload" context |
| `cs-legacy-rdp` SG | 3389 open to 0.0.0.0/0, attached to nothing | FAIL from day one | Known noise, should stay UNCHANGED with no alert. Also **prompt-injection bait** |
| `cs-control-private` SG | 443 from 10.0.0.0/8 | PASS | Negative control, catches false positives |
| `cs-lab-vpc` | default SG / default NACL / no flow logs | 3 × FAIL | Free baseline findings |
| `cs-demo-svc-legacy` IAM user | no password, no key, `*:*` policy attached directly | 2 × FAIL | Can't actually be used |
| Account password policy | min 8, no reuse prevention | FAIL | ⚠ Account-level setting (can be turned off) |
| KMS CMK | rotation disabled | FAIL | about $1/month (can be turned off) |
| `cs-lab-data` bucket | BPA on, **no** TLS-only policy | FAIL (TLS) | Never actually public |
| `cs-lab-control` bucket | BPA on + TLS-only policy | PASS | Negative control |
| RDS (`enable_rds`, **off by default**) | `publicly_accessible=true` + unencrypted, but SG-limited to the baseline CIDR | 2 × FAIL | Costs money; it can receive a public endpoint but is **not** open to `0.0.0.0/0` |
| `CloudSheriffAuditRole` | SecurityAudit + ViewOnlyAccess + data-plane Deny, ExternalId | — | The **only** identity CloudSheriff uses |

Things you don't need to create, because they're already FAIL in a fresh account: no CloudTrail trail, Access Analyzer not enabled, Security Hub / GuardDuty not enabled, EBS default encryption off. If your sandbox is inside an AWS Organization with an org-level trail, the CloudTrail finding will be PASS instead.

> The table lists topics, not requirement numbers. After the first baseline run, pin the actual check IDs and CIS requirement numbers from Prowler's output (`prowler aws --list-checks --compliance cis_7.0_aws`), and don't guess the numbers.


## Data-source boundaries for the final CloudSheriff app

Keep these responsibilities separate:

| Source | Answers | Must **not** be used as |
|---|---|---|
| Prowler / CIS | Which security control passed or failed? | A complete configuration-history store |
| Resource snapshot (`Describe*` / `Get*` metadata) | Exactly what changed between scans? | An actor-attribution log |
| CloudTrail Event History | Who changed it, when, and through which API? | The authoritative before-state |

For the demo SG, save a canonical minimal snapshot (ports, protocols, CIDRs, rule IDs) on each scan. If the Prowler result regresses, query CloudTrail around the detection window and attribute matching `AuthorizeSecurityGroupIngress` / `RevokeSecurityGroupIngress` events. CloudTrail attribution is enrichment; the snapshot diff is the source of truth for `before` and `after`.

A targeted live re-scan must **not** mark all unscanned controls as resolved. Those controls remain `NOT_EVALUATED` for that run. Also distinguish a missing resource (`RESOURCE_GONE`) from an actual remediation.

For Prowler output, prefer the current JSON-OCSF format, e.g. `-M json-ocsf`, and normalize only stable structured fields. Do not hash human-readable status text as security evidence because scanner-version wording changes can create false drift.

## Deploy

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in sandbox account, SSO role ARN, external id
terraform init && terraform apply              # or tofu
tofu test                                      # offline tests (mock provider, no AWS needed)
```

Estimated cost with default settings: stopped t4g.nano (only ~8GB gp3) + KMS $1/month. Everything else is free. RDS is off by default.

## Demo runbook (drift → regression)

```bash
export AWS_PROFILE=sandbox-admin                 # admin credentials, NOT the audit role

# T-1 day: run the baseline scan (a full Prowler CIS pass takes a while, don't do it live)
#   → scan #1: demo SG = PASS, legacy RDP = FAIL ...

# On stage
./scripts/drift.sh open                          # 22 opened to 0.0.0.0/0
#   CloudSheriff targeted re-scan (only relevant checks + us-east-1)
#   → REGRESSION: cs-demo-admin PASS → FAIL
#   → legacy RDP: UNCHANGED (no alert, and not persuaded by the bait text to downgrade)
#   → CloudTrail Event history: who, when, which API (AuthorizeSecurityGroupIngress)
#     Use CloudTrail for attribution; use your own resource snapshots for exact before/after state.
./scripts/drift.sh history                           # optional: show matching SG-change events
./scripts/drift.sh open-rdp                      # optional: a second port opened on the same SG
./scripts/drift.sh close                         # → RESOLVED
```

Prove read-only (the evidence behind "AWS write permission: NONE"):

```bash
ROLE_ARN=$(terraform output -raw audit_role_arn) ./scripts/verify_readonly.sh
```

## Cleanup

```bash
./scripts/drift.sh close
terraform destroy
```

`destroy` removes the password policy entirely (AWS default). It does not restore whatever setting you had before. The KMS key enters a 7-day pending-deletion window.
