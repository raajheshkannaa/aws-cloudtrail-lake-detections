import aws_cdk as cdk
from constructs import Construct

from .aws_cloudtrail_lake_detections_stack import CloudTrailLakeDetections

class PipelineStage(cdk.Stage):
	def __init__(self, scope: Construct, id: str, **kwargs):
		super().__init__(scope, id, **kwargs)

		stack = CloudTrailLakeDetections(self, 'CloudTrailLakeDetections-Stack')

