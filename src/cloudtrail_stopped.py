"""
Detection: CloudTrail Logging Stopped or Deleted

Detects when CloudTrail trails are deleted or logging is stopped.
This is a high-severity indicator — attackers disable logging to cover their tracks.

MITRE ATT&CK: T1562.008 (Impair Defenses: Disable Cloud Logs)
"""

from detection_base import (
    get_cloudtrail_lake_client, get_event_data_store_id,
    get_time_window, run_query, extract_event_json,
    send_slack_alert, deep_get, aws_cloudtrail_success,
    build_in_clause, logger
)

EVENT_NAMES = [
    'DeleteTrail',
    'StopLogging',
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

        user = (
            deep_get(ct_event, "userIdentity", "userName")
            or deep_get(ct_event, "userIdentity", "sessionContext", "sessionIssuer", "userName")
            or deep_get(ct_event, "userIdentity", "arn")
            or "unknown"
        )

        trail = deep_get(ct_event, "requestParameters", "name", default="unknown")

        message = (
            f"*CloudTrail Logging Disabled*\n"
            f"Action: `{ct_event.get('eventName')}`\n"
            f"Trail: `{trail}`\n"
            f"User: `{user}`\n"
            f"Account: `{deep_get(ct_event, 'recipientAccountId')}`\n"
            f"Region: `{deep_get(ct_event, 'awsRegion')}`"
        )
        send_slack_alert(message)
