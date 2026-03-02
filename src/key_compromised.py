"""
Detection: Compromised Access Key

Detects when AWS applies the quarantine policy AWSExposedCredentialPolicy_DO_NOT_REMOVE,
indicating an access key was found exposed (typically in a public GitHub repo).

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
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
        f"SELECT eventTime, recipientAccountId, eventJson "
        f"FROM {store_id} "
        f"WHERE eventName = 'PutUserPolicy' "
        f"AND eventTime > '{start}' AND eventTime < '{end}'"
    )

    results = run_query(client, query)
    for row in results:
        ct_event = extract_event_json(row)
        if not ct_event:
            continue

        params = ct_event.get("requestParameters", {})
        if params and params.get("policyName") == "AWSExposedCredentialPolicy_DO_NOT_REMOVE":
            message = (
                f"*Compromised Access Key Detected*\n"
                f"User: `{deep_get(ct_event, 'userIdentity', 'arn')}`\n"
                f"Access Key: `{deep_get(ct_event, 'userIdentity', 'accessKeyId')}`\n"
                f"Account: `{deep_get(ct_event, 'recipientAccountId')}`\n"
                f"AWS has applied the quarantine policy — this key was found exposed publicly."
            )
            send_slack_alert(message)
