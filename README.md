## CloudTrail Lake Threat Detections
Threat detections you can enable RIGHT NOW with the capability of AWS CloudTrail Lake.

All you need is to toggle couple switches in the Organization Account to enable CloudTrail Lake, which will collect cloudtrail logs from all accounts & regions and normalize those logs for us to query using sql. We will use lambda functions` to query the lake for threats and alert slack. 

Previously to do this at scale meant, enabling CloudTrail in all accounts and regions, sending those logs to S3 or a data lake has to be configured with partitions setup accordingly and athena queries to be scheduled. There are multiple moving parts to this equation, however with the announcement of CloudTrail Lake, all of this is extremely straight forward.

*Note*: Detections forked from Panther Labs CloudTrail Rules - https://github.com/panther-labs/panther-analysis/tree/master/aws_cloudtrail_rules
## Detections
```
- ami_modified_for_public_image
- resource_made_public
- snapshot_made_public
- key_compromised
- security_configuration_change
- codebuild_made_public
```
