from functools import reduce
from collections.abc import Mapping

	
def aws_cloudtrail_success(event):
	if event.get("errorCode", "") or event.get("errorMessage", ""):
		return False
	return True

def aws_event_tense(event_name):
	"""Convert an AWS CloudTrail eventName to be interpolated in alert titles
	An example is passing in StartInstance and returning 'started'.
	This would then be used in an alert title such as
	'The EC2 instance my-instance was started'.
	Args:
		event_name (str): The CloudTrail eventName
	Returns:
		str: A tensed version of the event name
	"""
	mapping = {
		"Create": "created",
		"Delete": "deleted",
		"Start": "started",
		"Stop": "stopped",
		"Update": "updated",
	}
	for event_prefix, tensed in mapping.items():
		if event_name.startswith(event_prefix):
			return tensed
	# If the event pattern doesn't exist, return original
	return event_name	

def deep_get(dictionary: dict, *keys, default=None):
	"""Safely return the value of an arbitrarily nested map
	Inspired by https://bit.ly/3a0hq9E
	"""
	return reduce(
		lambda d, key: d.get(key, default) if isinstance(d, Mapping) else default, keys, dictionary
	)
