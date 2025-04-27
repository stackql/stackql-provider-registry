*** Settings ***
Resource          ${CURDIR}/stackql.resource
Test Teardown     Stackql Per Test Teardown

*** Test Cases *** 
Simple Google Buckets List With Date Logic Contains Exemplifies Use of SQLite Math Functions
    Pass Execution If    "${SQL_BACKEND}" == "postgres_tcp"    This is a valid case where the test is targetted at SQLite only
    [Tags]   google   storage    buckets   gooogle.storage    google.storage.buckets    tier_1
    ${inputStr} =    Catenate
    ...    SELECT name, timeCreated, floor(julianday('2025-01-27')-julianday(timeCreated)) as days_since_ceiling 
    ...    FROM google.storage.buckets 
    ...    WHERE project = 'stackql-demo' 
    ...    order by name desc
    ...    ;
    Stock Stackql Exec Inline Contains Both Streams
    ...    ${inputStr}
    ...    days_since_ceiling
    ...    ${EMPTY}
    ...    Google-Buckets-List-With-Date-Logic-Contains-Exemplifies-Use-of-SQLite-Math-Functions

Simple Google IAM Service Accounts List
    Pass Execution If    "${SQL_BACKEND}" == "postgres_tcp"    This is a valid case where the test is targetted at SQLite only
    [Tags]   google   iam    service_accounts   gooogle.iam    google.iam.service_accounts    tier_1
    ${inputStr}=    Catenate
    ...    select email 
    ...    from google.iam.service_accounts 
    ...    where projectsId = 'stackql-robot' 
    ...    order by email desc
    ...    ;
    Stock Stackql Exec Inline Contains Both Streams
    ...    ${inputStr}
    ...    stackql\-robot\-rw\-sa@stackql\-robot.iam.gserviceaccount.com
    ...    ${EMPTY}
    ...    Google-Buckets-List-With-Date-Logic-Contains-Exemplifies-Use-of-SQLite-Math-Functions

AWS Route53 List Record Sets Simple
    [Documentation]    It is fine for this to dump 404 infor to stderr. So long as the empty reusult is represented with a header row, all good.
    [Tags]   aws   route53    resource_record_sets   aws.route53    aws.route53.resource_record_sets    tier_1
    ${inputStr} =    Catenate
    ...    select Name, Type, ResourceRecords 
    ...    from aws.route53.resource_record_sets 
    ...    where Id = '${AWS_RECORD_SET_ID}' 
    ...    and region = '${AWS_RECORD_SET_REGION}' 
    ...    order by Name, Type
    ...    ;
    Stock Stackql Exec Inline Contains Both Streams
    ...    ${inputStr}
    ...    ResourceRecords
    ...    ${EMPTY}
    ...    AWS-Route53-List-Record-Sets-Simple

# AWS IAM Users Subquery Left Joined With Aliasing and Name Collision
#     [Documentation]    AWS IAM Users Complex Query.  Acceptable to hardcoode region for global resource.
#     [Tags]   aws   iam    users   aws.iam    aws.iam.users  tier_1
#     ${inputStr} =    Catenate
#     ...    select u1.UserName, u.UserId, u.Arn, u1.region from ( select Arn, UserName, UserId from aws.iam.users where region = 'us-east-1' ) u inner join aws.iam.users u1 on u1.Arn = u.Arn where region = 'us-east-1'  order by u1.UserName desc;
#     Stock Stackql Exec Inline Contains Both Streams
#     ...    ${inputStr}
#     ...    UserName
#     ...    ${EMPTY}
#     ...    AWS-IAM-Users-Subquery-Left-Joined-With-Aliasing-and-Name-Collision
