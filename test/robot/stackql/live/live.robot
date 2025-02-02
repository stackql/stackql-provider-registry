*** Settings ***
Resource          ${CURDIR}/stackql.resource
Test Teardown     Stackql Per Test Teardown

*** Test Cases *** 
Google Buckets List With Date Logic Contains Exemplifies Use of SQLite Math Functions
    Pass Execution If    "${SQL_BACKEND}" == "postgres_tcp"    This is a valid case where the test is targetted at SQLite only
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
