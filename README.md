# CloudTrail Lake Threat Detections

Threat detection rules you can deploy RIGHT NOW using AWS CloudTrail Lake. SQL-based queries across your entire AWS Organization, with Lambda-based alerting to Slack.

For a full deep-dive on the architecture and why CloudTrail Lake over EventBridge, read the blog post: [Detection Engineering with CloudTrail Lake at Scale](https://docs.defensive.works/blog/detection-engineering-cloudtrail-lake/)

## Why CloudTrail Lake

Previously, to do detections at scale meant enabling CloudTrail in all accounts & regions, shipping logs to S3, setting up Glue crawlers & Athena partitions, and scheduling queries. Multiple moving parts.

CloudTrail Lake simplifies all of this — toggle a couple switches in the Organization Account, it collects cloudtrail logs from all accounts & regions, normalizes them, and you query with SQL. That's it.

## Architecture

```
    AWS Organization Account
    ┌─────────────────────────────────┐
    │  CloudTrail Lake                │
    │  (Org-wide Event Data Store)    │
    └──────────────┬──────────────────┘
                   │ cross-account role assumption
    Security/Automation Account
    ┌──────────────┴──────────────────┐
    │  EventBridge (every 10 min)     │
    │       │                         │
    │  ┌────┴────────────────────┐    │
    │  │ Lambda Functions (VPC)  │    │
    │  │                         │    │
    │  │ - resource_made_public  │    │
    │  │ - key_compromised       │    │
    │  │ - ami_public            │    │
    │  │ - snapshot_public       │    │
    │  │ - security_config       │    │
    │  │ - codebuild_public      │    │
    │  │ - cloudtrail_stopped    │    │
    │  └────┬────────────────────┘    │
    │       │                         │
    │     Slack                       │
    └─────────────────────────────────┘
```

Each detection is a Lambda function deployed via CDK. EventBridge triggers them every 10 minutes. The Lambda assumes a cross-account role to query CloudTrail Lake in the Organization account, evaluates results, and sends alerts to Slack.

Lambdas run in a VPC with NAT — so you get VPC Flow Logs on the detection infrastructure itself. Monitoring your monitors.

## Detections

| Detection | CloudTrail Events | MITRE ATT&CK | Severity |
|---|---|---|---|
| **Resource Made Public** | `PutBucketPolicy`, `SetRepositoryPolicy`, `PutKeyPolicy`, +8 more | T1537 | High |
| **Compromised Access Key** | `PutUserPolicy` (quarantine policy) | T1552.001 | Critical |
| **AMI Made Public** | `ModifyImageAttribute` | T1537 | High |
| **Snapshot Made Public** | `ModifySnapshotAttribute`, `ModifyDBSnapshotAttribute` | T1537 | High |
| **Security Config Tampering** | `DeleteTrail`, `StopLogging`, `DeleteDetector`, +7 more | T1562.001 | Critical |
| **CodeBuild Made Public** | `UpdateProjectVisibility` | T1552 | High |
| **CloudTrail Stopped** | `DeleteTrail`, `StopLogging` | T1562.008 | Critical |

## Prerequisites

1. **CloudTrail Lake Event Data Store** — Organization-wide, enabled in the management account
2. **Cross-account IAM roles** — see [IAM Setup](#iam-setup) below
3. **Slack incoming webhook** — for alert delivery
4. **AWS CDK** — for deployment (`npm install -g aws-cdk`)
5. **Python 3.12+**

## Deployment

```bash
# Clone the repo
git clone https://github.com/raajheshkannaa/aws-cloudtrail-lake-detections.git
cd aws-cloudtrail-lake-detections

# Copy and configure
cp config.py.example config.py
cp config.py.example src/config.py
# Edit both config.py files with your account IDs and Slack webhook URL

# Install dependencies
pip install -r requirements.txt

# Deploy
cdk bootstrap  # if not already done
cdk deploy
```

## IAM Setup

You need two IAM roles for cross-account access:

### 1. Hub Role (in Security/Automation Account)

Role name: `security/hub-001`

Trust policy: Allow the Lambda execution role to assume this role.

Permissions: Allow `sts:AssumeRole` on the CloudTrail Lake read role in the Org account.

### 2. CloudTrail Lake Read Role (in Organization Account)

Role name: `security/cloudtrail-lake-read-role`

Trust policy: Allow the hub role from the automation account to assume this role.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:StartQuery",
                "cloudtrail:GetQueryResults",
                "cloudtrail:ListEventDataStores",
                "cloudtrail:DescribeQuery"
            ],
            "Resource": "*"
        }
    ]
}
```

For the full cross-account IAM foundation (hub-spoke model), see [fleet-access](https://github.com/raajheshkannaa/fleet-access).

## Configuration

All configuration is in `config.py` (root level for CDK, `src/config.py` for Lambda runtime):

| Variable | Description |
|---|---|
| `AUTOMATION_ACCOUNT` | AWS account ID where the detection Lambdas run |
| `ORG_ACCOUNT` | AWS Organization management account ID |
| `CLOUDTRAIL_LAKE_READ_ROLE` | IAM role name in the Org account |
| `HOOK_URL` | Slack incoming webhook URL |

Values can also be set via environment variables: `AUTOMATION_ACCOUNT`, `ORG_ACCOUNT`, `CLOUDTRAIL_LAKE_READ_ROLE`, `SLACK_HOOK_URL`.

## Cost Estimate

CloudTrail Lake pricing is per-GB ingested and per-GB scanned.

| Component | Estimate (100 accounts) | Estimate (300+ accounts) |
|---|---|---|
| CloudTrail Lake ingestion | ~$50-150/month | ~$150-500/month |
| CloudTrail Lake queries (7 detections x 6/hour x 730 hours) | ~$10-30/month | ~$30-100/month |
| Lambda + NAT Gateway | ~$35/month | ~$35/month |
| **Total** | **~$95-215/month** | **~$215-635/month** |

Costs vary significantly based on event volume. Monitor your CloudTrail Lake usage in AWS Cost Explorer.

## How It Works

Each detection Lambda:

1. Assumes a cross-account role into the Organization account
2. Queries CloudTrail Lake with a SQL query targeting specific API events
3. Polls for query completion (with timeout and backoff)
4. Parses `eventJson` from results and evaluates detection logic
5. Sends structured alerts to Slack for positive detections

The query window looks back 20 minutes on a 10-minute schedule — the overlap ensures no events are missed due to CloudTrail Lake ingestion delays.

## Adding a New Detection

1. Create a new file in `src/` (e.g., `src/my_detection.py`)
2. Import from `detection_base` for shared functionality
3. Implement a `main(event, context)` handler
4. Add the detection name to the `DETECTIONS` list in `stacks/aws_cloudtrail_lake_detections_stack.py`
5. Deploy with `cdk deploy`

See any existing detection file for the pattern.

## Related Projects

- [fleet-access](https://github.com/raajheshkannaa/fleet-access) — Hub-spoke IAM role foundation (prerequisite)
- [green-stone](https://github.com/raajheshkannaa/green-stone) — Security Group change detection & response
- [attack-surface-management](https://github.com/raajheshkannaa/attack-surface-management) — External AWS service discovery & scanning

Detection logic originally forked from [Panther Labs CloudTrail Rules](https://github.com/panther-labs/panther-analysis/tree/master/aws_cloudtrail_rules), adapted for CloudTrail Lake.

## License

MIT
