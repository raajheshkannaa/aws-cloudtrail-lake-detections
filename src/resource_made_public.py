import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta
from time import sleep
import json
from urllib.request import urlopen, URLError, HTTPError, Request
from config import HOOK_URL, ORG_ACCOUNT, CLOUDTRAIL_LAKE_READ_ROLE

from policyuniverse.policy import Policy
from base_helpers import helper

APPROVAL_HOOK_URL = HOOK_URL

time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
delta = (datetime.now(timezone.utc) - timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S") # AWS CloudWatch Event is triggered every 10 mins, where as here the delta looks back 11 minutes to have some overlap so that no event is missed due to time differences in 'seconds'

print("Current = {}\nDelta = {}".format(time, delta))

def assume_role(session, aws_account_number, role_name):
	resp = session.client('sts').assume_role(
		RoleArn='arn:aws:iam::{}:role/security/{}'.format(aws_account_number,role_name),
		RoleSessionName='Defensive.Works')

	# Storing STS credentials
	creds = boto3.Session(
		aws_access_key_id = resp['Credentials']['AccessKeyId'],
		aws_secret_access_key = resp['Credentials']['SecretAccessKey'],
		aws_session_token = resp['Credentials']['SessionToken']
	)

	print("Assumed session for {}.".format(
		aws_account_number
	))

	return creds



def send_slack_message(event):
	
	userType = event['userIdentity']['type']
	if userType == "AssumedRole":
		userName = (event['userIdentity']['arn']).split('/')[2]
	else: # This means its an IAM User
		userName = event['userIdentity']['userName']

	account = event['userIdentity']["accountId"]
	region = event["awsRegion"]

	if event.get("Resources"):
		resource = event.get('Resources')[0].get('arn', 'MISSING')
	else:
		resource = event.get('eventSource', 'MISSING SOURCE')

	slack_message = {
		'text': 'Request ID: ' + str(event["requestID"]) + '\n*' + str(userName) + '* made resource *' + str(resource) + '* public, in account *' + str(account) + '*' + ' in region *' + region + '*'
	}		

	try:
		request = Request(APPROVAL_HOOK_URL, method='POST')
		request.add_header('Content-Type', 'application/json')
		data = json.dumps(slack_message)
		data = data.encode()
		response = urlopen(request, data)
		if response.status == 200:
			print("Message posted to approval channel")
			return('200')

	except HTTPError as e:
		print("Request failed: " + e.code + " " + e.reason)
	except URLError as e:
		print("Server connection failed: " + e.reason) 


# Check that the IAM policy allows resource accessibility via the Internet
def policy_is_internet_accessible(json_policy):
	if json_policy is None:
		return False
	return Policy(json_policy).is_internet_accessible()


def main(event, context):

	session = assume_role(boto3.Session(), ORG_ACCOUNT, CLOUDTRAIL_LAKE_READ_ROLE)

	client = session.client('cloudtrail', region_name = 'us-east-1')

	event_data_stores = client.list_event_data_stores()['EventDataStores']
	
	for data_store in event_data_stores:
		Name = data_store['Name']
		database = data_store['EventDataStoreArn'].split('/')[1]
	
	event_name = ('PutBucketPolicy', 'SetRepositoryPolicy', 'CreateElasticsearchDomain', 'UpdateElasticsearchDomainConfig', 'CreateKey', 'PutKeyPolicy', 'SetVaultAccessPolicy', 'SetQueueAttributes', 'CreateTopic', 'SetTopicAttributes', 'PutResourcePolicy')

	
	query = "SELECT requestId, eventTime, recipientAccountId, awsRegion, eventJson, eventName FROM {} WHERE eventName in '{}' AND eventTime > '{}' AND eventTime < '{}'".format(database, event_name, delta, time)

	run_query = client.start_query(
		QueryStatement = query
	)

	queryid = run_query['QueryId']

	sleep(3)

	query_results = client.get_query_results(
	EventDataStore=database,
	QueryId=queryid
	)

	for results in query_results['QueryResultRows']:
		for result in results:
			for k,v in result.items():
				if k == 'eventJson':			
					event = v
				if k == 'requestId':
					requestid = v


			# Normally this check helps avoid overly complex functions that are doing too many things,
			# but in this case we explicitly want to handle 10 different cases in 10 different ways.
			# Any solution that avoids too many return statements only increases the complexity of this rule.
			# pylint: disable=too-many-return-statements
				if not helper.aws_cloudtrail_success(event):
					return False

				parameters = event.get("requestParameters", {})
				# Ignore events that are missing request params
				if not parameters:
					return False

				policy = ""

				# S3
				if event["eventName"] == "PutBucketPolicy":
					return policy_is_internet_accessible(parameters.get("bucketPolicy"))

				# ECR
				if event["eventName"] == "SetRepositoryPolicy":
					policy = parameters.get("policyText", {})

				# Elasticsearch
				if event["eventName"] in ["CreateElasticsearchDomain", "UpdateElasticsearchDomainConfig"]:
					policy = parameters.get("accessPolicies", {})

				# KMS
				if event["eventName"] in ["CreateKey", "PutKeyPolicy"]:
					policy = parameters.get("policy", {})

				# S3 Glacier
				if event["eventName"] == "SetVaultAccessPolicy":
					policy = helper.deep_get(parameters, "policy", "policy", default={})

				# SNS & SQS
				if event["eventName"] in ["SetQueueAttributes", "CreateTopic"]:
					policy = helper.deep_get(parameters, "attributes", "Policy", default={})

				# SNS
				if (
					event["eventName"] == "SetTopicAttributes"
					and parameters.get("attributeName", "") == "Policy"
				):
					policy = parameters.get("attributeValue", {})

				# SecretsManager
				if event["eventName"] == "PutResourcePolicy":
					policy = parameters.get("resourcePolicy", {})

				if not policy:
					return False

				if policy_is_internet_accessible(json.loads(policy)):
					send_slack_message(event)