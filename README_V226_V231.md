# V226-V231 Deep Operational Excellence

This layer deepens the most important operator capabilities without creating an autonomous unrestricted exploitation path.

## V226 Exploitation Intelligence
- Loads findings through the shared array/JSONL/wrapper/single-object loader.
- Classifies high-interest findings.
- Selects registered safe proof adapters.
- Scores exploitability/evidence quality.
- Records proof prerequisites and explicit forbidden capabilities.

## V227 Validation Excellence
- Builds finding-aware validation records.
- Enforces non-empty scope and explicit approval for execution.
- Delegates actual safe proof to the existing V37 guard/adapter architecture.

## V228 Active Directory
- Generates a read-only AD assessment plan.
- Optional approved execution uses NetExec (`nxc`) for SMB baseline, users, groups, password policy and shares.
- Credentials are supplied through environment variables and are not persisted in evidence.
- No spraying, credential dumping, Kerberoasting, AS-REP roasting, privilege changes, persistence or lateral movement.

## V229 AWS
- Account-bound read-only AWS CLI inventory.
- Verifies caller identity before inventory.
- Reviews IAM account summary, users, roles, S3 buckets and EC2 security groups.
- Execution requires `AWS_ALLOWED_ACCOUNT_IDS` plus explicit approval.
- No secret/key retrieval and no resource mutation.

## V230 Web/API
- Evidence-backed coverage checks for endpoint inventory, API surface, authentication, object authorization and business-logic review.
- Explicit blind spots are produced instead of assuming coverage.

## V231 Quality Gate
- Verifies all V226-V230 artifacts exist.
- Produces operator handoff and safety state.

## CLI
Plan-only deep stack:
`python3 orchestrator.py -c CLIENT -t TARGET --deep-excellence`

Read-only AD execution (authorized scope required):
`NXC_USER=... NXC_PASSWORD=... python3 orchestrator.py -c CLIENT -t TARGET --ad-execute --scope-file config/scope.example.txt`

Read-only AWS execution (authorized account required):
`AWS_ALLOWED_ACCOUNT_IDS=123456789012 python3 orchestrator.py -c CLIENT -t TARGET --aws-execute --aws-account-id 123456789012`

The AD/AWS execution paths require a second interactive approval and remain read-only.
