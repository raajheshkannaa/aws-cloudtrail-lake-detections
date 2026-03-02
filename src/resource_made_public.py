"""
Detection: Resource Made Public

Detects when AWS resources are made internet-accessible via policy changes.
Covers: S3, ECR, OpenSearch, KMS, Glacier, SQS, SNS, SecretsManager.

MITRE ATT&CK: T1537 (Transfer Data to Cloud Account), T1190 (Exploit Public-Facing Application)
"""

import json
from policyuniverse.policy import Policy
from detection_base import (
    get_cloudtrail_lake_client, get_event_data_store_id,
    get_time_window, run_query, extract_event_json,
    send_slack_alert, deep_get, aws_cloudtrail_success,
    build_in_clause, logger
)

EVENT_NAMES = [
    'PutBucketPolicy',
    'SetRepositoryPolicy',
    'CreateElasticsearchDomain',
    'UpdateElasticsearchDomainConfig',
    'CreateKey',
    'PutKeyPolicy',
    'SetVaultAccessPolicy',
    'SetQueueAttributes',
    'CreateTopic',
    'SetTopicAttributes',
    'PutResourcePolicy',
]


def policy_is_internet_accessible(json_policy):
    if json_policy is None:
        return False
    if isinstance(json_policy, str):
        json_policy = json.loads(json_policy)
    return Policy(json_policy).is_internet_accessible()


def evaluate(event):
    """Evaluate whether the event indicates a resource was made public."""
    if not aws_cloudtrail_success(event):
        return False

    params = event.get("requestParameters", {})
    if not params:
        return False

    event_name = event.get("eventName", "")
    policy = None

    if event_name == "PutBucketPolicy":
        return policy_is_internet_accessible(params.get("bucketPolicy"))
    elif event_name == "SetRepositoryPolicy":
        policy = params.get("policyText", {})
    elif event_name in ("CreateElasticsearchDomain", "UpdateElasticsearchDomainConfig"):
        policy = params.get("accessPolicies", {})
    elif event_name in ("CreateKey", "PutKeyPolicy"):
        policy = params.get("policy", {})
    elif event_name == "SetVaultAccessPolicy":
        policy = deep_get(params, "policy", "policy", default={})
    elif event_name in ("SetQueueAttributes", "CreateTopic"):
        policy = deep_get(params, "attributes", "Policy", default={})
    elif event_name == "SetTopicAttributes" and params.get("attributeName") == "Policy":
        policy = params.get("attributeValue", {})
    elif event_name == "PutResourcePolicy":
        policy = params.get("resourcePolicy", {})

    if not policy:
        return False

    return policy_is_internet_accessible(policy)


def main(event, context):
    client = get_cloudtrail_lake_client()
    store_id = get_event_data_store_id(client)
    start, end = get_time_window()

    in_clause = build_in_clause(EVENT_NAMES)
    query = (
        f"SELECT eventTime, recipientAccountId, awsRegion, eventJson, eventName "
        f"FROM {store_id} "
        f"WHERE eventName IN {in_clause} "
        f"AND eventTime > '{start}' AND eventTime < '{end}'"
    )

    results = run_query(client, query)
    for row in results:
        ct_event = extract_event_json(row)
        if ct_event and evaluate(ct_event):
            resource = "unknown"
            if ct_event.get("resources"):
                resource = ct_event['resources'][0].get('arn', 'unknown')
            else:
                resource = ct_event.get('eventSource', 'unknown')

            message = (
                f"*Resource Made Public*\n"
                f"User: `{deep_get(ct_event, 'userIdentity', 'arn')}`\n"
                f"Resource: `{resource}`\n"
                f"Account: `{deep_get(ct_event, 'recipientAccountId')}`\n"
                f"Region: `{deep_get(ct_event, 'awsRegion')}`\n"
                f"Action: `{ct_event.get('eventName')}`"
            )
            send_slack_alert(message)
