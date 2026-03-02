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

# All detection handlers to deploy
DETECTIONS = [
    'resource_made_public',
    'key_compromised',
    'ami_modified_for_public_image',
    'snapshot_made_public',
    'security_configuration_change',
    'codebuild_made_public',
    'cloudtrail_stopped',
]


class CloudTrailLakeDetections(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        src_role_arn = f'arn:aws:iam::{AUTOMATION_ACCOUNT}:role/security/hub-001'
        src_role = iam.Role.from_role_arn(self, 'Role', src_role_arn)

        subnet1 = ec2.SubnetConfiguration(
            name="Public",
            subnet_type=ec2.SubnetType.PUBLIC,
            cidr_mask=24,
        )
        subnet2 = ec2.SubnetConfiguration(
            name="Private",
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            cidr_mask=24,
        )

        vpc = ec2.Vpc(
            self, "CloudTrailLakeDetectionsVPC",
            ip_addresses=ec2.IpAddresses.cidr("10.187.0.0/16"),
            enable_dns_hostnames=True,
            enable_dns_support=True,
            max_azs=2,
            nat_gateway_provider=ec2.NatProvider.gateway(),
            nat_gateways=1,
            subnet_configuration=[subnet1, subnet2],
        )

        # EventBridge rule — triggers all detections every 10 minutes
        rule = events.Rule(
            self, "TriggerCloudTrailLakeDetections",
            schedule=events.Schedule.rate(Duration.minutes(10)),
        )

        # Deploy each detection as a Lambda function
        for detection_name in DETECTIONS:
            fn = lmb.Function(
                self, detection_name,
                code=lmb.Code.from_asset('src/'),
                runtime=lmb.Runtime.PYTHON_3_12,
                handler=f'{detection_name}.main',
                timeout=Duration.seconds(120),
                memory_size=128,
                role=src_role,
                function_name=f'ctlake-{detection_name}',
                vpc=vpc,
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
            )
            rule.add_target(targets.LambdaFunction(fn))
