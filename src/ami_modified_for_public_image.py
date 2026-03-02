"""
Detection: AMI Made Public

Detects when an EC2 AMI launch permission is modified to allow public access.
AMIs can contain credentials, application code, and sensitive data.

MITRE ATT&CK: T1537 (Transfer Data to Cloud Account)
"""

from detection_base import (
    get_cloudtrail_lake_client, get_event_data_store_id,
    get_time_window, run_query, extract_event_json,
    send_slack_alert, deep_get, aws_cloudtrail_success, logger
)


def main(event, context):
    client = get_cloudtrail_lake_client()
    store_id = get_event_data_store_id(client)
    start, end = get_time_window()

    query = (
        f"SELECT eventTime, recipientAccountId, awsRegion, eventJson "
        f"FROM {store_id} "
        f"WHERE eventName = 'ModifyImageAttribute' "
        f"AND eventTime > '{start}' AND eventTime < '{end}'"
    )

    results = run_query(client, query)
    for row in results:
        ct_event = extract_event_json(row)
        if not ct_event or not aws_cloudtrail_success(ct_event):
            continue

        added_perms = deep_get(
            ct_event, "requestParameters", "launchPermission", "add", "items", default=[]
        )
        for item in added_perms:
            if item.get('group') == 'all':
                message = (
                    f"*AMI Made Public*\n"
                    f"User: `{deep_get(ct_event, 'userIdentity', 'arn')}`\n"
                    f"Image: `{deep_get(ct_event, 'requestParameters', 'imageId')}`\n"
                    f"Account: `{deep_get(ct_event, 'recipientAccountId')}`\n"
                    f"Region: `{deep_get(ct_event, 'awsRegion')}`"
                )
                send_slack_alert(message)
