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
