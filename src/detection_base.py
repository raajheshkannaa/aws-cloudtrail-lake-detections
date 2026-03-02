"""
Shared base module for CloudTrail Lake detections.

Handles cross-account role assumption, CloudTrail Lake query execution
with proper polling, Slack alerting, and time window management.
"""

import boto3
import json
import logging
from datetime import datetime, timezone, timedelta
from time import sleep
from functools import reduce
from collections.abc import Mapping
from urllib.request import urlopen, Request, HTTPError, URLError

from config import HOOK_URL, ORG_ACCOUNT, CLOUDTRAIL_LAKE_READ_ROLE

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Maximum time to wait for a CloudTrail Lake query to complete
QUERY_TIMEOUT_SECONDS = 60
QUERY_POLL_INTERVAL_SECONDS = 2
LOOKBACK_MINUTES = 20


def get_time_window():
    """Compute the query time window at invocation time, not at module load."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(minutes=LOOKBACK_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    end = now.strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Query window: {start} -> {end}")
    return start, end


def assume_role(session, account_id, role_name):
    """Assume a cross-account IAM role and return a new boto3 session."""
    resp = session.client('sts').assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/security/{role_name}',
        RoleSessionName='CloudTrailLakeDetections'
    )
    creds = boto3.Session(
        aws_access_key_id=resp['Credentials']['AccessKeyId'],
        aws_secret_access_key=resp['Credentials']['SecretAccessKey'],
        aws_session_token=resp['Credentials']['SessionToken']
    )
    logger.info(f"Assumed role in account {account_id}")
    return creds


def get_cloudtrail_lake_client():
    """Assume into the org account and return a CloudTrail client."""
    session = assume_role(boto3.Session(), ORG_ACCOUNT, CLOUDTRAIL_LAKE_READ_ROLE)
    return session.client('cloudtrail', region_name='us-east-1')


def get_event_data_store_id(client):
    """Get the first event data store ID from CloudTrail Lake."""
    stores = client.list_event_data_stores()['EventDataStores']
    if not stores:
        raise RuntimeError("No CloudTrail Lake event data stores found")
    store_id = stores[0]['EventDataStoreArn'].split('/')[1]
    logger.info(f"Using event data store: {stores[0]['Name']} ({store_id})")
    return store_id


def run_query(client, query_statement):
    """Execute a CloudTrail Lake query with proper polling for completion.

    Returns a list of result rows, or an empty list if no results.
    Replaces the old sleep(3) pattern with actual status checking.
    """
    response = client.start_query(QueryStatement=query_statement)
    query_id = response['QueryId']

    elapsed = 0
    while elapsed < QUERY_TIMEOUT_SECONDS:
        sleep(QUERY_POLL_INTERVAL_SECONDS)
        elapsed += QUERY_POLL_INTERVAL_SECONDS

        results = client.get_query_results(
            EventDataStore=get_event_data_store_id(client),
            QueryId=query_id
        )
        status = results.get('QueryStatus', 'UNKNOWN')

        if status == 'FINISHED':
            return results.get('QueryResultRows', [])
        elif status in ('FAILED', 'CANCELLED'):
            logger.error(f"Query {query_id} {status}: {results.get('ErrorMessage', 'unknown error')}")
            return []

    logger.error(f"Query {query_id} timed out after {QUERY_TIMEOUT_SECONDS}s")
    return []


def extract_event_json(result_row):
    """Extract and parse the eventJson field from a CloudTrail Lake result row.

    CloudTrail Lake returns eventJson as a JSON string — it needs to be parsed.
    """
    for item in result_row:
        for k, v in item.items():
            if k == 'eventJson':
                if isinstance(v, str):
                    return json.loads(v)
                return v
    return None


def send_slack_alert(message):
    """Send an alert message to Slack. Returns True on success."""
    payload = json.dumps({'text': message}).encode()
    try:
        request = Request(HOOK_URL, method='POST')
        request.add_header('Content-Type', 'application/json')
        response = urlopen(request, payload)
        if response.status == 200:
            logger.info("Alert sent to Slack")
            return True
        else:
            logger.error(f"Slack returned status {response.status}")
            return False
    except HTTPError as e:
        logger.error(f"Slack request failed: {e.code} {e.reason}")
        return False
    except URLError as e:
        logger.error(f"Slack connection failed: {e.reason}")
        return False


def deep_get(dictionary, *keys, default=None):
    """Safely retrieve a value from a nested dictionary."""
    return reduce(
        lambda d, key: d.get(key, default) if isinstance(d, Mapping) else default,
        keys, dictionary
    )


def aws_cloudtrail_success(event):
    """Check if a CloudTrail event completed successfully (no error)."""
    if event.get("errorCode", "") or event.get("errorMessage", ""):
        return False
    return True


def build_in_clause(event_names):
    """Build a properly formatted SQL IN clause from a list of event names."""
    quoted = ", ".join(f"'{name}'" for name in event_names)
    return f"({quoted})"
