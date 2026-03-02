"""
Detection: Security Configuration Tampering

Detects when security controls are disabled or deleted — often an indicator
that an attacker is covering their tracks before proceeding.

MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
"""

from detection_base import (
    get_cloudtrail_lake_client, get_event_data_store_id,
    get_time_window, run_query, extract_event_json,
    send_slack_alert, deep_get, aws_cloudtrail_success,
    build_in_clause, logger
)

EVENT_NAMES = [
    'DeleteAccountPublicAccessBlock',
    'DeleteDeliveryChannel',
    'DeleteDetector',
    'DeleteFlowLogs',
    'DeleteRule',
    'DeleteTrail',
    'DisableEbsEncryptionByDefault',
    'DisableRule',
    'StopConfigurationRecorder',
    'StopLogging',
]

# Known automation roles that legitimately perform these actions
ALLOW_LIST = [
    # Add your known automation role names here
    # 'OrganizationAccountAccessRole',
    # 'AWSControlTowerExecution',
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
        if not ct_event:
            continue

        if not aws_cloudtrail_success(ct_event):
            continue

        user = (
            deep_get(ct_event, "userIdentity", "userName")
            or deep_get(ct_event, "userIdentity", "sessionContext", "sessionIssuer", "userName")
            or "unknown"
        )

        if user in ALLOW_LIST:
            continue

        message = (
            f"*Security Configuration Change*\n"
            f"Action: `{ct_event.get('eventName')}`\n"
            f"User: `{user}`\n"
            f"Account: `{deep_get(ct_event, 'recipientAccountId')}`\n"
            f"Region: `{deep_get(ct_event, 'awsRegion')}`"
        )
        send_slack_alert(message)
