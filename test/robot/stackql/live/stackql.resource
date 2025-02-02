*** Variables ***
${REPOSITORY_ROOT}                     ${CURDIR}${/}..${/}..${/}..${/}..
${CORE_REPOSITORY_ROOT}                ${REPOSITORY_ROOT}${/}stackql-core
${CORE_LIB_HOME}                       ${CORE_REPOSITORY_ROOT}${/}test${/}robot${/}lib
${LOCAL_LIB_HOME}                      ${CURDIR}${/}..${/}..${/}lib
${EXECUTION_PLATFORM}                  native   # to be overridden from command line, eg "docker"
${SQL_BACKEND}                         sqlite_embedded   # to be overridden from command line, eg "postgres_tcp"
${IS_WSL}                              false   # to be overridden from command line, with string "true"
${SHOULD_RUN_DOCKER_EXTERNAL_TESTS}    false   # to be overridden from command line, with string "true"
${CONCURRENCY_LIMIT}                   1       # to be overridden from command line, with integer value, -1 for no limit
${USE_STACKQL_PREINSTALLED}            false   # to be overridden from command line, with string "true"
${SUNDRY_CONFIG}                       {}  # to be overridden from command line, with string value
${CORE_PREFIX}                         stackql-core

*** Settings ***
Library           Process
Library           OperatingSystem 
Variables         ${CORE_LIB_HOME}/stackql_context.py    ${EXECUTION_PLATFORM}    ${SQL_BACKEND}    ${USE_STACKQL_PREINSTALLED}
...               ${SUNDRY_CONFIG}
Library           Process
Library           OperatingSystem
Library           String
Library           ${CORE_LIB_HOME}/StackQLInterfaces.py    ${EXECUTION_PLATFORM}    ${SQL_BACKEND}    ${CONCURRENCY_LIMIT}
Library           ${CORE_LIB_HOME}/CloudIntegration.py

*** Keywords ***


Prepare StackQL Environment
    Sleep    10s

Stock Stackql Exec Inline Equals Both Streams
    [Arguments]    ${inputStr}    ${outputStr}    ${outputStderrStr}    ${tmpFileTrunk}
    Should Stackql Exec Inline Equal Both Streams
    ...    ${STACKQL_EXE}
    ...    ${OKTA_SECRET_STR}
    ...    ${GITHUB_SECRET_STR}
    ...    ${K8S_SECRET_STR}
    ...    ${REGISTRY_NO_VERIFY_CFG_STR}
    ...    {}
    ...    ${SQL_BACKEND_CFG_STR_CANONICAL}
    ...    ${inputStr}
    ...    ${outputStr}
    ...    ${outputStderrStr}
    ...    stdout=${CURDIR}${/}tmp${/}${tmpFileTrunk}.tmp
    ...    stderr=${CURDIR}${/}tmp${/}${tmpFileTrunk}-stderr.tmp

Stock Stackql Exec Inline Contains Both Streams
    [Arguments]    ${inputStr}    ${outputStr}    ${outputStderrStr}    ${tmpFileTrunk}
    Should Stackql Exec Inline Contain Both Streams
    ...    ${STACKQL_EXE}
    ...    ${OKTA_SECRET_STR}
    ...    ${GITHUB_SECRET_STR}
    ...    ${K8S_SECRET_STR}
    ...    ${REGISTRY_NO_VERIFY_CFG_STR}
    ...    {}
    ...    ${SQL_BACKEND_CFG_STR_CANONICAL}
    ...    ${inputStr}
    ...    ${outputStr}
    ...    ${outputStderrStr}
    ...    stdout=${CURDIR}${/}tmp${/}${tmpFileTrunk}.tmp
    ...    stderr=${CURDIR}${/}tmp${/}${tmpFileTrunk}-stderr.tmp


Stackql Per Test Teardown
    IF    "${EXECUTION_PLATFORM}" == "docker" and "${SQL_BACKEND}" == "postgres_tcp"
        ${res} =         Run Process    bash    \-c    docker kill $(docker ps \-\-filter name\=execrun \-q)
        Log     Container killed
        # Should Be Equal As Integers    ${res.rc}    0
        ${restwo} =         Run Process    bash    \-c    docker rm $(docker ps \-\-filter status\=exited \-q)
        Log     Container removed
        # Should Be Equal As Integers    ${restwo.rc}    0
    END
