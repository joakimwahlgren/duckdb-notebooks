# CloudTrail Analysis
Demo dataset: http://summitroute.com/downloads/flaws_cloudtrail_logs.tar

## Initiate or attach a persistent database named 'cloudtrail.db'
```sql
/** Initiate or attach a persistent 'cloudtrail.db' database.
*/

ATTACH IF NOT EXISTS 'cloudtrail.db' AS cloudtrail_db;
```

## Import the CloudTrail logs and create two tables.
```sql
/** Import the CloudTrail logs and create two tables.
Set "maximum_object_size" for the flaws dataset.
Not required for standard CloudTrail datasets.
*/
CREATE OR REPLACE TABLE ct_raw AS
    WITH raw_data AS (
        SELECT * 
        FROM read_json(
            'cloudtrail/flaws_cloudtrail_logs/*.json.gz',
            maximum_depth=2,
            maximum_object_size=146800640,
            sample_size=-1
        )
    )
    SELECT unnest(Records) AS Event
    FROM raw_data;

CREATE OR REPLACE TABLE cloudtrail_events AS SELECT
    -- Standard Top-Level Event Metadata
    json_extract_string(Event, '$.eventVersion') AS eventVersion,
    CAST(json_extract_string(Event, '$.eventTime') AS TIMESTAMP) AS eventTime, 
    json_extract_string(Event, '$.eventSource') AS eventSource,
    json_extract_string(Event, '$.eventName') AS eventName,
    json_extract_string(Event, '$.eventType') AS eventType,
    json_extract_string(Event, '$.awsRegion') AS awsRegion,
    json_extract_string(Event, '$.sourceIPAddress') AS sourceIPAddress,
    json_extract_string(Event, '$.userAgent') AS userAgent,

    -- User Identity Details
    json_extract_string(Event, '$.userIdentity.type') AS userIdentityType,
    json_extract_string(Event, '$.userIdentity.principalId') AS userIdentityPrincipalId,
    json_extract_string(Event, '$.userIdentity.arn') AS userIdentityArn,
    json_extract_string(Event, '$.userIdentity.accountId') AS userIdentityAccountId,
    json_extract_string(Event, '$.userIdentity.accessKeyId') AS userIdentityAccessKeyId,
    json_extract_string(Event, '$.userIdentity.userName') AS userIdentityUserName,

    -- Session Context
    json_extract_string(Event, '$.userIdentity.sessionContext.attributes.mfaAuthenticated') AS mfaAuthenticated,
    json_extract_string(Event, '$.userIdentity.sessionContext.attributes.creationDate') AS sessionCreationDate,
  
    -- Full Request Parameters (as JSON)
    json_extract(Event, '$.requestParameters') AS requestParameters,

    -- Basic Request Parameters
    json_extract_string(Event, '$.requestParameters.bucketName') AS requestBucketName,
    json_extract_string(Event, '$.requestParameters.key') AS requestKey,
    json_extract_string(Event, '$.requestParameters.groupName') AS requestGroupName,
    json_extract_string(Event, '$.requestParameters.groupId') AS requestGroupId,
    json_extract_string(Event, '$.requestParameters.vpcId') AS requestVpcId,
    json_extract_string(Event, '$.requestParameters.subnetId') AS requestSubnetId,
    json_extract_string(Event, '$.requestParameters.securityGroupId') AS requestSecurityGroupId,
  
    -- Full Response Elements (as JSON)
    json_extract(Event, '$.responseElements') as responseElements,
  
    -- Full Resources Parameters (as JSON)
    json_extract(Event, '$.resources') AS resources
  FROM ct_raw;
```

## Return all Fields and Values.
```sql
-- Return all fields and values.

SELECT * FROM cloudtrail_events
ORDER BY eventTime;
```

## Event summary
```sql
-- event summary

SELECT 
  eventName, 
  count(*) AS eventCount 
FROM cloudtrail_events
GROUP BY eventName
ORDER BY eventCount DESC;
```

## IP summary (excluding *.amazonaws.com and AWS Internal)
```sql
-- IP summary (excluding *.amazonaws.com and AWS Internal)

SELECT 
  sourceIPAddress,
  count(*) AS srcipCount 
FROM cloudtrail_events WHERE
  sourceIPAddress NOT LIKE '%.amazonaws.com' AND
  sourceIPAddress NOT LIKE 'AWS Internal'
GROUP BY sourceIPAddress 
ORDER BY srcipCount DESC;
```

## Activity by specific IP address
```sql
-- Activity by specific IP address

SELECT 
  eventName, 
  count(*) AS eventCount 
FROM cloudtrail_events
  WHERE sourceIPAddress = 'xx.xx.xx.xx'
GROUP BY eventName
ORDER BY eventCount DESC;
```

## Return values from requestParameters or responseElements
```sql
-- Return array values from requestParameters or responseElements

SELECT 
  eventTime,
  eventType,
  eventSource,
  eventName,
  sourceIPAddress,
  requestParameters.groupId,
  requestParameters.ipPermissions.items[0].ipRanges.items[0].cidrIp AS cidrIp,
  requestParameters.ipPermissions.items[0].ipRanges.items[0].description AS description,
  -- requestParameters,
  -- responseElements,
  awsRegion
  FROM cloudtrail_events
  WHERE sourceIPAddress = 'xx.xx.xx.xx'
  AND eventName = 'AuthorizeSecurityGroupIngress'
ORDER BY eventTime;
```

## Initial Access
```sql
-- Initial Access
-- Source: https://github.com/invictus-ir/aws-cheatsheet

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'ConsoleLogin',
  'PasswordRecoveryRequested'
  )
ORDER BY eventTime;
```

## Execution
```sql
-- Execution

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'StartInstance',
  'StartInstances',
  'Invoke',
  'SendCommand'
  )
ORDER BY eventTime;
```

## Example Query - Pivot on suspicious userArn and src IP.
```sql
-- Example Query - Pivot on suspicious userArn and src IP.
-- Source: github.com/easttimor/aws-incident-response

SELECT 
  eventName, 
  count(*) AS eventCount 
FROM cloudtrail_events WHERE 
  userIdentityArn = 'arn:aws:iam::811596193553:user/Level6' 
  AND sourceIPAddress = '5.205.62.253'
GROUP BY eventName ORDER BY eventCount DESC;
```

## Persistence
```sql
-- Persistence

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'CreateAccessKey',
  'CreateUser',
  'CreateNetworkAclEntry',
  'CreateRoute',
  'CreateLoginProfile',
  'AuthorizeSecurityGroupEgress',
  'AuthorizeSecurityGroupIngress',
  'CreateVirtualMFADevice',
  'CreateConnection',
  'ApplySecurityGroupsToLoadBalancer',
  'SetSecurityGroups',
  'AuthorizeDBSecurityGroupIngress',
  'CreateDBSecurityGroup',
  'ChangePassword')
ORDER BY eventTime;
```

## Privilege Escalation
```sql
-- Privilege Escalation

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'CreateGroup',
  'CreateRole',
  'UpdateAccessKey',
  'PutGroupPolicy',
  'PutRolePolicy',
  'PutUserPolicy',
  'AddRoleToInstanceProfile',
  'AddUserToGroup'
  )
ORDER BY eventTime;
```

## Defense Evasion
```sql
-- Defense Evasion

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'StopLogging',
  'DeleteTrail',
  'UpdateTrail',
  'PutEventSelectors',
  'DeleteFlowLogs',
  'DeleteDetector',
  'DeleteMembers',
  'DeleteSnapshot,'
  'DeactivateMFADevice',
  'DeleteCertificate',
  'DeleteConfigRule',
  'DeleteAccessKey',
  'LeaveOrganization',
  'DisassociateFromMasterAccount',
  'DisassociateMembers',
  'StopMonitoringMembers'
  )
ORDER BY eventTime;
```

## Credential Access
```sql
-- Credential Access

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'GetSecretValue',
  'GetPasswordData',
  'RequestCertificate',
  'UpdateAssumeRolePolicy'
  )
ORDER BY eventTime;
```

## Discovery
```sql
-- Discovery

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'ListUsers',
  'ListRoles',
  'ListIdentities',
  'ListAccessKeys',
  'ListServiceQuotas',
  'ListInstanceProfiles',
  'ListBuckets',
  'ListGroups',
  'GetSendQuota',
  'GetCallerIdentity',
  'DescribeInstances',
  'GetBucketAcl',
  'GetBucketVersioning',
  'GetAccountAuthorizationDetails'
  )
ORDER BY eventTime;
```

## Lateral Movement
```sql
-- Lateral Movement

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'AssumeRole',
  'SwitchRole'
  )
ORDER BY eventTime;
```

## Exfiltration
```sql
-- Exfiltration

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'CreateSnapShot',
  'ModifySnapshotAttributes',
  'ModifyImageAttribute',
  'SharedSnapshotCopyInitiated',
  'SharedSnapshotVolumeCreated',
  'ModifyDBSnapshotAttribute',
  'PutBucketPolicy',
  'PutBucketAcl'
  )
ORDER BY eventTime;
```

## Impact
```sql
-- Impact

SELECT * FROM cloudtrail_events
  WHERE eventName IN 
  (
  'PutBucketVersioning',
  'RunInstances',
  'DeleteAccountPublicAccessBlock'
  )
ORDER BY eventTime;
```
