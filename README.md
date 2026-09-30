# CloudSheriff Lab: intentionally misconfigured AWS test environment

A lab environment for demoing and testing CloudSheriff (read-only CIS drift monitor).

> **Scope:** this repository contains the AWS test fixture and the CloudSheriff pipeline in `cloudsheriff/`. See [`docs/reference/hacksprint-boundary.md`](docs/reference/hacksprint-boundary.md) for what was built before and during the event.
**Deploy it only in a dedicated sandbox AWS account.** Two guards prevent mistakes:

1. The provider sets `allowed_account_ids`, so it refuses to run against any other account.
2. You must explicitly set `i_understand_this_is_insecure = true`, otherwise `plan` fails immediately.

## What it deploys

| Resource | State | Expected CIS 7.0 result | Role in the demo |
|---|---|---|---|
| `cs-demo-admin` SG | SSH only from `10.10.0.0/16` | **PASS** (baseline) | ★ Drift target: `drift.sh open` → REGRESSION |
| `production-web-01` (t4g.nano, **stopped**) | IMDSv1, root volume unencrypted, attached to demo SG | FAIL (IMDSv2) | Gives the AI "production workload" context |
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

Things you don't need to create, because they're already FAIL in a fresh account: no CloudTrail trail, Access Analyzer not enabled, Security Hub not enabled, EBS default encryption off. If your sandbox is inside an AWS Organization with an org-level trail, the CloudTrail finding will be PASS instead.

CIS 7.0 checks regional EBS *encryption-by-default* (`ec2_ebs_default_encryption`), not the encryption of this specific root volume, so the instance row only guarantees the IMDSv2 finding.

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

## Quick start

Deploy the AWS lab once ([Deploy](#deploy)), then record a baseline and run a drift scan ([Run the pipeline](#run-the-pipeline)).

## Deploy

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in sandbox account, SSO role ARN, external id
tofu init && tofu apply
tofu test                                      # offline tests (mock provider, no AWS needed)
```

Terraform must be version 1.7 or newer to run `terraform test`.

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

## AWS access (dedicated member account)

The lab runs in its own AWS Organizations member account, never in the management account. All tools (aws CLI, OpenTofu, boto3) use a repo-local profile, selected by `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE` and `AWS_PROFILE=cs-sandbox` in `.env`. The gitignored `.aws/` directory holds:

```ini
# .aws/credentials: management-account IAM user key
[cs-mgmt]
aws_access_key_id = ...
aws_secret_access_key = ...

# .aws/config: admin in the lab account via the role Organizations creates
[profile cs-mgmt]
region = us-east-1
[profile cs-sandbox]
role_arn = arn:aws:iam::<lab-account-id>:role/OrganizationAccountAccessRole
source_profile = cs-mgmt
region = us-east-1
```

Do not put AWS keys in `.env`. Environment-variable credentials take precedence over the profile and would point every tool at the management account.

`terraform/bootstrap/` manages the member account itself from the management account (`profile = "cs-mgmt"`). Set `lab_account_id` to adopt an existing account through an `import` block, or leave it null to create one. `prevent_destroy` guards against closing the account by accident.

```bash
tofu -chdir=terraform/bootstrap init && tofu -chdir=terraform/bootstrap plan
```

## Run the pipeline

Prowler uses `--scan-unused-services` so unattached security groups remain visible to the scanner, including the known-noise and negative-control fixtures.

```bash
cp .env.example .env            # fill in keys; never commit .env
surreal start --user root --pass root surrealkv://data/cloudsheriff.db   # separate terminal
uv run python -m cloudsheriff build-image      # once; builds the Daytona snapshot with Prowler
uv run python -m cloudsheriff scan --baseline  # record baseline, no alerts
./scripts/drift.sh open                         # admin creds
# wait for CloudTrail delivery (measured ~2 min on 2026-09-30); until then attribution shows "pending"
uv run python -m cloudsheriff scan             # REGRESSION alert + attribution + explanation (traced in Arize)
./scripts/drift.sh close && uv run python -m cloudsheriff scan   # RESOLVED
uv run pytest -q
```

Prove read-only (the evidence behind "AWS write permission: NONE"):

```bash
ROLE_ARN=$(tofu -chdir=terraform output -raw audit_role_arn) ./scripts/verify_readonly.sh
```

## Verify

```bash
uv run pytest -q                  # offline unit tests (70 passed, 1 skipped on 2026-09-30)
tofu -chdir=terraform test        # Terraform tests with a mock provider, no AWS needed (6 passed)
ROLE_ARN=$(tofu -chdir=terraform output -raw audit_role_arn) ./scripts/verify_readonly.sh   # audit role cannot write
```

## Cleanup

```bash
./scripts/drift.sh close
terraform destroy
```

`destroy` removes the password policy entirely (AWS default). It does not restore whatever setting you had before. The KMS key enters a 7-day pending-deletion window.
