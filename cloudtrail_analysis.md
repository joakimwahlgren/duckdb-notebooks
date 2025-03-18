# CloudTrail Analysis
## Initiate or attach a persistent database named 'cloudtrail.db'
### Demo dataset: http://summitroute.com/downloads/flaws_cloudtrail_logs.tar

```sql
/** Initiate or attach a persistent 'cloudtrail.db' database.
*/

ATTACH IF NOT EXISTS 'cloudtrail.db' AS ctdb;
```

## Import the raw logs to the database.
```sql
/** Import the raw logs to the database.
Source: https://qiita.com/nakaniko/items/bed8a7b808760ffb3338

Modify the maximum file size of decompressed json files.
Default by DuckDB is 16777216 bytes.
CloudTrail default is 50MB.

maximum_object_size=52428800
Ref: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html#cloudtrail-resource-quotas
*/

CREATE TABLE ct_raw AS
    WITH raw_data AS (
        SELECT * 
        FROM read_json(
            'cloudtrail/*/*.json.gz',
            maximum_depth=2,
            maximum_object_size=146800640,
            sample_size=-1
        )
    )
    SELECT unnest(Records) AS Event
    FROM raw_data;

CREATE TABLE ct_detail AS
SELECT
    json_extract_string(Event, '$.eventVersion') AS eventVersion,
    json_extract_string(Event, '$.eventTime') AS eventTime,
    json_extract_string(Event, '$.eventSource') AS eventSource,
    json_extract_string(Event, '$.eventName') AS eventName,
    json_extract_string(Event, '$.awsRegion') AS awsRegion,
    json_extract_string(Event, '$.sourceIPAddress') AS sourceIPAddress,
    json_extract_string(Event, '$.userAgent') AS userAgent,
    json_extract_string(Event, '$.userIdentity.type') AS userType,
    json_extract_string(Event, '$.userIdentity.principalId') AS principalId,
    json_extract_string(Event, '$.userIdentity.arn') AS userArn,
    json_extract_string(Event, '$.userIdentity.accountId') AS accountId,
    json_extract_string(Event, '$.userIdentity.accessKeyId') AS accessKeyId,
    json_extract_string(Event, '$.userIdentity.userName') AS userName,
    json_extract_string(Event, '$.userIdentity.sessionContext.attributes.creationDate') AS sessionCreationDate,
    json_extract_string(Event, '$.userIdentity.sessionContext.attributes.mfaAuthenticated') AS mfaAuthenticated,
    json_extract_string(json_extract(Event, '$.requestParameters.instancesSet.items[0]'), '$.instanceId') AS instanceId1,
    json_extract_string(json_extract(Event, '$.requestParameters.instancesSet.items[1]'), '$.instanceId') AS instanceId2,
    json_extract_string(json_extract(Event, '$.responseElements.instancesSet.items[0]'), '$.instanceId') AS responseInstanceId1,
    json_extract_string(json_extract(Event, '$.responseElements.instancesSet.items[0]'), '$.currentState.name') AS responseCurrentState1,
    json_extract_string(json_extract(Event, '$.responseElements.instancesSet.items[0]'), '$.previousState.name') AS responsePreviousState1,

    json_extract_string(json_extract(Event, '$.responseElements.instancesSet.items[1]'), '$.instanceId') AS responseInstanceId2,
    json_extract_string(json_extract(Event, '$.responseElements.instancesSet.items[1]'), '$.currentState.name') AS responseCurrentState2,
    json_extract_string(json_extract(Event, '$.responseElements.instancesSet.items[1]'), '$.previousState.name') AS responsePreviousState2,
    json_extract_string(Event, '$.requestID') AS requestID,
    json_extract_string(Event, '$.eventID') AS eventID,
    json_extract_string(Event, '$.readOnly') AS readOnly,
    json_extract_string(Event, '$.eventType') AS eventType,
    json_extract_string(Event, '$.managementEvent') AS managementEvent,
    json_extract_string(Event, '$.recipientAccountId') AS recipientAccountId,
    json_extract_string(Event, '$.eventCategory') AS eventCategory,
    json_extract_string(Event, '$.tlsDetails.tlsVersion') AS tlsVersion,
    json_extract_string(Event, '$.tlsDetails.cipherSuite') AS cipherSuite,
    json_extract_string(Event, '$.tlsDetails.clientProvidedHostHeader') AS clientProvidedHostHeader
FROM ct_raw;
```

## Return all Fields and Values.
```sql
/** Return all fields and values.

Use filter options of this pivot table to narrow down by fields and values.
Or modify the below query for selected fields, for example

SELECT
  eventTime,
  eventType,
  eventSource,
  eventName,
  userName,
  sourceIPAddress,
  userAgent,
  awsRegion
FROM ct_detail
ORDER BY eventTime;

*/

SELECT * FROM ct_detail
ORDER BY eventTime;
```

## Initial Access
```sql
/** Initial Access
Source: https://github.com/invictus-ir/aws-cheatsheet

Use filter options of this pivot table to narrow down by fields and values.

or modify the below query for selected fields, for example

SELECT
  eventTime,
  eventType,
  eventSource,
  eventName,
  userName,
  sourceIPAddress,
  userAgent,
  awsRegion
FROM ct_detail
*/

SELECT * FROM ct_detail
  WHERE eventName IN 
  (
  'ConsoleLogin',
  'PasswordRecoveryRequested'
  )
ORDER BY eventTime;
```

## Execution
```sql
/** Execution
Source: https://github.com/invictus-ir/aws-cheatsheet
*/
SELECT * FROM ct_detail
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
/** Example Query - Pivot on suspicious userArn and src IP.
Source: github.com/easttimor/aws-incident-response
*/

SELECT 
  eventName, 
  count(*) AS eventCount 
FROM ct_detail WHERE 
  userArn = 'arn:aws:iam::811596193553:user/Level6' 
  AND sourceIPAddress = '5.205.62.253'
GROUP BY eventName ORDER BY eventCount DESC;
```

## Persistence
```sql
/** Persistence
Source: https://github.com/invictus-ir/aws-cheatsheet
*/
SELECT * FROM ct_detail
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
/** Privilege Escalation
Source: https://github.com/invictus-ir/aws-cheatsheet
*/
SELECT * FROM ct_detail
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
/** Defense Evasion
Source: https://github.com/invictus-ir/aws-cheatsheet
*/
SELECT * FROM ct_detail
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
/** Credential Access
Source: https://github.com/invictus-ir/aws-cheatsheet
*/
SELECT * FROM ct_detail
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
/** Discovery
Source: https://github.com/invictus-ir/aws-cheatsheet
*/
SELECT * FROM ct_detail
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
/** Lateral Movement
Source: https://github.com/invictus-ir/aws-cheatsheet
*/
SELECT * FROM ct_detail
  WHERE eventName IN 
  (
  'AssumeRole',
  'SwitchRole'
  )
ORDER BY eventTime;
```

## Exfiltration
```sql
/** Exfiltration
Source: https://github.com/invictus-ir/aws-cheatsheet
*/
SELECT * FROM ct_detail
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
/** Impact
Source: https://github.com/invictus-ir/aws-cheatsheet
*/
SELECT * FROM ct_detail
  WHERE eventName IN 
  (
  'PutBucketVersioning',
  'RunInstances',
  'DeleteAccountPublicAccessBlock'
  )
ORDER BY eventTime;
```
