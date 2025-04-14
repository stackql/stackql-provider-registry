*** Settings ***
Resource          ${CURDIR}/stackql.resource
Test Teardown     Stackql Per Test Teardown

*** Test Cases *** 
Google Buckets Lifecycle
    [Documentation]    This test case inserts a bucket ("row") into the google.storage.buckets "table", checks the row was inserted, deletes the row, and checks the row was deleted.
    [Tags]   google   storage    buckets   gooogle.storage    google.storage.buckets
    ${insertInputStr} =    Catenate
    ...    insert into google.storage.buckets(data__name, project) 
    ...    select '${GCS_BUCKET_NAME}', '${GCP_PROJECT}';
    ${checkInputStr} =    Catenate
    ...    select name, "softDeleteTime", "hardDeleteTime" from google.storage.buckets where bucket = '${GCS_BUCKET_NAME}';
    ${deleteInputStr} =    Catenate
    ...    delete from google.storage.buckets where bucket = '${GCS_BUCKET_NAME}';
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${insertInputStr}
    ...    ${EMPTY}
    ...    The operation was despatched successfully
    ...    Google-Buckets-Lifecycle-Insert
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${checkInputStr}
    ...    ${EXPECTED_GCS_BUCKET_CHECK}
    ...    ${EMPTY}
    ...    Google-Buckets-Lifecycle-Post-Insert-Check
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${deleteInputStr}
    ...    ${EMPTY}
    ...    The operation was despatched successfully
    ...    Google-Buckets-Lifecycle-Delete
    Sleep    5s
    Stock Stackql Exec Inline Equals Stdout
    ...    ${checkInputStr}
    ...    ${EXPECTED_EMPTY_GCS_BUCKET_CHECK}
    ...    Google-Buckets-Lifecycle-Post-Delete-Check

Google Network Lifecycle
    [Documentation]    This test case inserts a VPC network then a subnet then mutates the subnet then deletes it and then deletes the network.
    [Tags]   google   compute    networks   subnetworks    vpc   gooogle.compute    google.compute.networks    google.compute.subnetworks    Google${SPACE}Networks
    ${insertNetworkInputStr} =    Catenate
    ...    insert into google.compute.networks(data__name, data__autoCreateSubnetworks, project) 
    ...    select 'robot-vpc-01', false, '${GCP_PROJECT}';
    ${insertSubnetInputStr} =    Catenate
    ...    insert into google.compute.subnetworks(
    ...    data__name, 
    ...    data__ipCidrRange, 
    ...    data__description, 
    ...    data__network, 
    ...    project,
    ...    region) 
    ...    select 
    ...    'robot-subnet-01', 
    ...    '10.0.0.0/8',
    ...    'An immutable subnet description.', 
    ...    'projects/${GCP_PROJECT}/global/networks/robot-vpc-01',
    ...    '${GCP_PROJECT}',
    ...    'australia-southeast1'
    ...    ;
    ${getNetworkDetailQueryStr} =    Catenate
    ...    select name, description, subnetworks
    ...    from google.compute.networks
    ...    where
    ...    name = 'robot-vpc-01'
    ...    and project = '${GCP_PROJECT}';
    ${getSubnetDetailQueryStr} =    Catenate
    ...    select name, secondaryIpRanges, fingerprint
    ...    from google.compute.subnetworks
    ...    where
    ...    name = 'robot-subnet-01'
    ...    and region = 'australia-southeast1'
    ...    and project = '${GCP_PROJECT}'
    ...    ;
    ${insertNetworkInputStr} =    Catenate
    ...    insert into google.compute.networks(data__name, data__autoCreateSubnetworks, project) 
    ...    select 'robot-vpc-01', false, '${GCP_PROJECT}';
    ${deleteNetworkStr} =    Catenate
    ...    delete from google.compute.networks where network = 'robot-vpc-01' and project = '${GCP_PROJECT}';
    ${deleteSubnetStr} =    Catenate
    ...    delete from google.compute.subnetworks where subnetwork = 'robot-subnet-01' and project = '${GCP_PROJECT}' and region = 'australia-southeast1';
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${insertNetworkInputStr}
    ...    ${EMPTY}
    ...    The operation was despatched successfully
    ...    Google-Network-Lifecycle-Insert-Network
    Sleep    20s
    ${networkResult} =    Catenate     SEPARATOR=\n
    ...    |--------------|-------------|-------------|
    ...    |${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}name${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}|${SPACE}description${SPACE}|${SPACE}subnetworks${SPACE}|
    ...    |--------------|-------------|-------------|
    ...    |${SPACE}robot-vpc-01${SPACE}|${SPACE}null${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}|${SPACE}null${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}|
    ...    |--------------|-------------|-------------|
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${getNetworkDetailQueryStr}
    ...    ${networkResult}
    ...    ${EMPTY}
    ...    Google-Network-Lifecycle-Select-Network-01
    Sleep    20s
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${insertSubnetInputStr}
    ...    ${EMPTY}
    ...    The operation was despatched successfully
    ...    Google-Network-Lifecycle-Insert-Subnet
    Sleep    20s
    ${networkDetailResult} =   Run Process
    ...    ${STACKQL_EXE}
    ...    \-\-output\=json
    ...    \-\-registry
    ...    ${REGISTRY_LOCAL_NO_VERIFY_CFG_STR}
    ...    exec
    ...    ${getNetworkDetailQueryStr}
    ...    stdout=${CURDIR}${/}tmp${/}Google-Network-Lifecycle-get-network-detail-1.tmp
    ...    stderr=${CURDIR}${/}tmp${/}Google-Network-Lifecycle-get-network-detail-1-stderr.tmp
    Log    Detail dict string = ${networkDetailResult.stdout}
    ${networkDetailDictList} =    Evaluate    json.loads($networkDetailResult.stdout)
    Log    Detail is:${networkDetailDictList}[0]
    Should Contain    ${networkDetailDictList[0]["subnetworks"]}    robot\-subnet\-01
    ${detailResult} =   Run Process
    ...    ${STACKQL_EXE}
    ...    \-\-output\=json
    ...    \-\-registry
    ...    ${REGISTRY_LOCAL_NO_VERIFY_CFG_STR}
    ...    exec
    ...    ${getSubnetDetailQueryStr}
    ...    stdout=${CURDIR}${/}tmp${/}Google-Network-Lifecycle-get-subnet-detail-1.tmp
    ...    stderr=${CURDIR}${/}tmp${/}Google-Network-Lifecycle-get-subnet-detail-1-stderr.tmp
    Log    Detail dict string = ${detailResult.stdout}
    ${detailDict} =    Evaluate    json.loads($detailResult.stdout)
    Should Be Equal    ${detailDict[0]["name"]}    robot\-subnet\-01
    ${CAPTURED_FINGERPRINT} =    Set Variable    ${detailDict[0]["fingerprint"]}
    ${updateSubnetInputStr} =    Catenate
    ...    update google.compute.subnetworks
    ...    SET
    ...    data__secondaryIpRanges = '[
    ...       {
    ...         "ipCidrRange": "192.168.0.0/24",
    ...         "rangeName": "s-r-01"
    ...       }
    ...     ]', 
    ...    data__fingerprint = '${CAPTURED_FINGERPRINT}'
    ...    WHERE
    ...    project = '${GCP_PROJECT}'
    ...    and
    ...    region = 'australia-southeast1'
    ...    and
    ...    subnetwork = 'robot-subnet-01'
    ...    ;
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${updateSubnetInputStr}
    ...    ${EMPTY}
    ...    The operation was despatched successfully
    ...    Google-Buckets-Lifecycle-Delete
    Sleep    30s
    ${updatedDetailResult} =   Run Process
    ...    ${STACKQL_EXE}
    ...    \-\-output\=json
    ...    \-\-registry
    ...    ${REGISTRY_LOCAL_NO_VERIFY_CFG_STR}
    ...    exec
    ...    ${getSubnetDetailQueryStr}
    ...    stdout=${CURDIR}${/}tmp${/}Google-Network-Lifecycle-get-subnet-detail-2.tmp
    ...    stderr=${CURDIR}${/}tmp${/}Google-Network-Lifecycle-get-subnet-detail-2-stderr.tmp
    Log    Updated detail dict string = ${updatedDetailResult.stdout}
    ${updatedDetailDict} =    Evaluate    json.loads($updatedDetailResult.stdout)
    Should Contain    ${updatedDetailDict[0]["secondaryIpRanges"]}    192.168.0.0/24
    Sleep    30s
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${deleteSubnetStr}
    ...    ${EMPTY}
    ...    ${EMPTY}
    ...    Google-Network-Lifecycle-Subnet-Delete
    Sleep    20s
    ${networkZeroSubnetResult} =    Catenate     SEPARATOR=\n
    ...    |--------------|-------------|-------------|
    ...    |${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}name${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}|${SPACE}description${SPACE}|${SPACE}subnetworks${SPACE}|
    ...    |--------------|-------------|-------------|
    ...    |${SPACE}robot-vpc-01${SPACE}|${SPACE}null${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}|${SPACE}null${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}|
    ...    |--------------|-------------|-------------|
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${getNetworkDetailQueryStr}
    ...    ${networkZeroSubnetResult}
    ...    ${EMPTY}
    ...    Google-Network-Lifecycle-Select-Network-02
    Sleep    60s
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${deleteNetworkStr}
    ...    ${EMPTY}
    ...    ${EMPTY}
    ...    Google-Network-Lifecycle-Network-Delete
    Sleep    20s
    ${networkEmptyResult} =    Catenate     SEPARATOR=\n
    ...    |------|-------------|-------------|
    ...    |${SPACE}name${SPACE}|${SPACE}description${SPACE}|${SPACE}subnetworks${SPACE}|
    ...    |------|-------------|-------------|
    Stock Stackql Exec Inline Equals Both Streams
    ...    ${getNetworkDetailQueryStr}
    ...    ${networkEmptyResult}
    ...    ${EMPTY}
    ...    Google-Network-Lifecycle-Select-Network-03
    

