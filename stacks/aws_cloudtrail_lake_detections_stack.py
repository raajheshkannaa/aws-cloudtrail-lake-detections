from constructs import Construct
from aws_cdk import (
	Duration,
	Stack,
	aws_lambda as lmb,
	aws_events as events,
	aws_events_targets as targets,
	aws_iam as iam,
	aws_ec2 as ec2,
)

from .config import AUTOMATION_ACCOUNT

class CloudTrailLakeDetections(Stack):

	def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
		super().__init__(scope, construct_id, **kwargs)

		# Depends on the `Hub` IAM ROLE present in the Security or Automation Account.
		src_role_arn = 'arn:aws:iam::' + AUTOMATION_ACCOUNT + ':role/security/hub-001'
		src_role = iam.Role.from_role_arn(self, 'Role', src_role_arn)

		# Subnet configurations for a public and private tier
		subnet1 = ec2.SubnetConfiguration(
				name="Public",
				subnet_type=ec2.SubnetType.PUBLIC,
				cidr_mask=24)
		subnet2 = ec2.SubnetConfiguration(
				name="Private",
				subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,
				cidr_mask=24)

		vpc = ec2.Vpc(self,
				  "CloudTrailLakeDetectionsVPC",
				  cidr="10.187.0.0/16", # Please change this if this would cause a conflict.
				  enable_dns_hostnames=True,
				  enable_dns_support=True,
				  max_azs=2,
				  nat_gateway_provider=ec2.NatProvider.gateway(),
				  nat_gateways=1,
				  subnet_configuration=[subnet1, subnet2]
				  )


		detection1 = lmb.Function(
			self, 'ami_modified_for_public_image',
			code=lmb.Code.from_asset('src/'),
			runtime=lmb.Runtime.PYTHON_3_9,
			handler='ami_modified_for_public_image.main',
			timeout=Duration.seconds(900),
			memory_size=128,
			role=src_role,
			function_name='ami_modified_for_public_image',
			vpc=vpc,
			vpc_subnets=ec2.SubnetType.PRIVATE_WITH_NAT,
		)

		detection2 = lmb.Function(
			self, 'snapshot_made_public',
			code=lmb.Code.from_asset('src/'),
			runtime=lmb.Runtime.PYTHON_3_9,
			handler='snapshot_made_public.main',
			timeout=Duration.seconds(900),
			memory_size=128,
			role=src_role,
			function_name='snapshot_made_public',
			vpc=vpc,
			vpc_subnets=ec2.SubnetType.PRIVATE_WITH_NAT,
		)

		detection3 = lmb.Function(
			self, 'resource_made_public',
			code=lmb.Code.from_asset('src/'),
			runtime=lmb.Runtime.PYTHON_3_9,
			handler='resource_made_public.main',
			timeout=Duration.seconds(900),
			memory_size=128,
			role=src_role,
			function_name='resource_made_public',
			vpc=vpc,
			vpc_subnets=ec2.SubnetType.PRIVATE_WITH_NAT,
		)


		rule = events.Rule(
			self, "TriggerCloudTrailLakeDetections",
			schedule=events.Schedule.rate(Duration.minutes(10))
		)

		rule.add_target(targets.LambdaFunction(detection1))
		rule.add_target(targets.LambdaFunction(detection2))
		rule.add_target(targets.LambdaFunction(detection3))
