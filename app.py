#!/usr/bin/env python3

import aws_cdk as cdk

from stacks.aws_cloudtrail_lake_detections_stack import CloudTrailLakeDetections

app = cdk.App()
CloudTrailLakeDetections(app, 'CloudTrailLakeDetections-PipelineStack')
app.synth()
