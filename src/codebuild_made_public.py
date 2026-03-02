"""
Detection: CodeBuild Project Made Public

Detects when a CodeBuild project visibility is set to PUBLIC_READ.
Build logs often contain environment variables, IAM credentials, and internal URLs.

MITRE ATT&CK: T1552 (Unsecured Credentials)
"""

from detection_base import (
    get_cloudtrail_lake_client, get_event_data_store_id,
    get_time_window, run_query, extract_event_json,
    send_slack_alert, deep_get, logger
)


def main(event, context):
    client = get_cloudtrail_lake_client()
    store_id = get_event_data_store_id(client)
    start, end = get_time_window()

    query = (
        f"SELECT eventTime, recipientAccountId, awsRegion, eventJson "
        f"FROM {store_id} "
        f"WHERE eventName = 'UpdateProjectVisibility' "
        f"AND eventTime > '{start}' AND eventTime < '{end}'"
    )

    results = run_query(client, query)
    for row in results:
        ct_event = extract_event_json(row)
        if not ct_event:
            continue

        if deep_get(ct_event, "requestParameters", "projectVisibility") == "PUBLIC_READ":
            message = (
                f"*CodeBuild Project Made Public*\n"
                f"User: `{deep_get(ct_event, 'userIdentity', 'arn')}`\n"
                f"Project: `{deep_get(ct_event, 'requestParameters', 'projectArn')}`\n"
                f"Account: `{deep_get(ct_event, 'recipientAccountId')}`\n"
                f"Region: `{deep_get(ct_event, 'awsRegion')}`"
            )
            send_slack_alert(message)
