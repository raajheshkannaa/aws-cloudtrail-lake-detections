import aws_cdk as cdk
from aws_cdk import (
	aws_codecommit as codecommit,
	pipelines as pipelines
)
from .deploy import PipelineStage
from constructs import Construct

from .config import AUTOMATION_ACCOUNT

class PipelineStack(cdk.Stack):

	def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
		super().__init__(scope, construct_id, **kwargs)

		# Create a codecommit repository called 'AttackSurfaceManagement'
		repo = codecommit.Repository(
			self, 'CloudTrailLakeDetections',
			repository_name='CloudTrailLakeDetections'
		)


		pipeline = pipelines.CodePipeline(
			self, 'Pipeline',
			synth=pipelines.ShellStep("Synth",
				input=pipelines.CodePipelineSource.code_commit(repo, 'master'),
				commands=[
					"npm install -g aws-cdk",
					"pip install -r requirements.txt",
					"npx cdk synth"
					]
				)
		)

		deploy_stage = pipeline.add_stage(PipelineStage(
			self, 'CloudTrailLakeDetectionsDeployment')			
		)