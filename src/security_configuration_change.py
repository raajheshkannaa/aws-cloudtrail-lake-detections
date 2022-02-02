import boto3
from datetime import datetime, timezone, timedelta
from time import sleep
import json
from urllib.request import urlopen, URLError, HTTPError, Request
from config import HOOK_URL, ORG_ACCOUNT, CLOUDTRAIL_LAKE_READ_ROLE

from base_helpers import deep_get, aws_cloudtrail_success

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


def send_slack_message(message):

	slack_message = {
		'text': message
	}

	try:
		request = Request(APPROVAL_HOOK_URL, method='POST')
		request.add_header('Content-Type', 'application/json')
		data = json.dumps(slack_message).encode()
		response = urlopen(request, data)
		if response.status == 200:
			print("Message posted to approval channel")
			return('200')

	except HTTPError as e:
		print("Request failed: " + e.code + " " + e.reason)
	except URLError as e:
		print("Server connection failed: " + e.reason) 



def main(event, context):

	session = assume_role(boto3.Session(), ORG_ACCOUNT, CLOUDTRAIL_LAKE_READ_ROLE)
	client = session.client('cloudtrail', region_name = 'us-east-1')
	event_data_stores = client.list_event_data_stores()['EventDataStores']
	
	for data_store in event_data_stores:
		Name = data_store['Name']
		database = data_store['EventDataStoreArn'].split('/')[1]
	
	event_name = (
	"DeleteAccountPublicAccessBlock",
	"DeleteDeliveryChannel",
	"DeleteDetector",
	"DeleteFlowLogs",
	"DeleteRule",
	"DeleteTrail",
	"DisableEbsEncryptionByDefault",
	"DisableRule",
	"StopConfigurationRecorder",
	"StopLogging",
	)

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

	ALLOW_LIST = [
		# Add expected events and users here to suppress alerts
		# {"userName": "ExampleUser or ExampleRole", "eventName": "ExampleEvent"},
		"ExampleUser",
		"ExampleRole"
	]

	for results in query_results['QueryResultRows']:
		for result in results:
			for k,v in result.items():
				if k == 'eventJson':			
					event = v
					
					if aws_cloudtrail_success(event):
						user = deep_get(event, "userIdentity", "userName") or deep_get(
						event, "userIdentity", "sessionContext", "sessionIssuer", "userName"
						)

						if user not in ALLOW_LIST:

							message = "Sensitive AWS API call {} made by {} in account {}".format(
								event.get('eventName'),
								user,
								deep_get(event, "recipientAccountId")
							)
							send_slack_message(message)