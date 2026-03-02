"""
Detection: Snapshot Made Public

Detects when EC2 EBS snapshots or RDS snapshots are made publicly accessible.
Snapshots can contain database dumps, credentials, and application data.

MITRE ATT&CK: T1537 (Transfer Data to Cloud Account)
"""

from collections.abc import Mapping
from detection_base import (
    get_cloudtrail_lake_client, get_event_data_store_id,
    get_time_window, run_query, extract_event_json,
    send_slack_alert, deep_get, aws_cloudtrail_success,
    build_in_clause, logger
)

EVENT_NAMES = [
    'ModifySnapshotAttribute',
    'ModifyDBSnapshotAttribute',
    'ModifyDBClusterSnapshotAttribute',
]


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
        if not ct_event or not aws_cloudtrail_success(ct_event):
            continue

        event_name = ct_event.get("eventName", "")
        params = ct_event.get("requestParameters", {})
        is_public = False
        resource_id = "unknown"

        # EC2 EBS Snapshot
        if event_name == "ModifySnapshotAttribute":
            if params.get("attributeType") != "CREATE_VOLUME_PERMISSION":
                continue
            items = deep_get(params, "createVolumePermission", "add", "items", default=[])
            for item in items:
                if isinstance(item, (Mapping, dict)) and item.get("group") == "all":
                    is_public = True
            resource_id = params.get("snapshotId", "unknown")

        # RDS Snapshot
        elif event_name in ("ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"):
            if "all" in deep_get(ct_event, "requestParameters", "valuesToAdd", default=[]):
                is_public = True
            resource_id = params.get("dBSnapshotIdentifier", params.get("dBClusterSnapshotIdentifier", "unknown"))

        if is_public:
            message = (
                f"*Snapshot Made Public*\n"
                f"User: `{deep_get(ct_event, 'userIdentity', 'arn')}`\n"
                f"Snapshot: `{resource_id}`\n"
                f"Account: `{deep_get(ct_event, 'recipientAccountId')}`\n"
                f"Region: `{deep_get(ct_event, 'awsRegion')}`\n"
                f"Type: `{event_name}`"
            )
            send_slack_alert(message)
