*** Variables ***
${REPOSITORY_ROOT}                     ${CURDIR}${/}..${/}..${/}..${/}..
${CORE_REPOSITORY_ROOT}                ${REPOSITORY_ROOT}${/}stackql-core
${CORE_LIB_HOME}                       ${CORE_REPOSITORY_ROOT}${/}test${/}python${/}stackql_test_tooling
${LOCAL_LIB_HOME}                      ${CURDIR}${/}..${/}..${/}lib
${EXECUTION_PLATFORM}                  native   # to be overridden from command line, eg "docker"
${SQL_BACKEND}                         sqlite_embedded   # to be overridden from command line, eg "postgres_tcp"
${IS_WSL}                              false   # to be overridden from command line, with string "true"
${SHOULD_RUN_DOCKER_EXTERNAL_TESTS}    false   # to be overridden from command line, with string "true"
${CONCURRENCY_LIMIT}                   1       # to be overridden from command line, with integer value, -1 for no limit
${USE_STACKQL_PREINSTALLED}            false   # to be overridden from command line, with string "true"
${SUNDRY_CONFIG}                       {}  # to be overridden from command line, with string value
${CORE_PREFIX}                         stackql-core
${CWD_FOR_EXEC}                        ${CORE_REPOSITORY_ROOT}  # works for self repository, can be overwritten when shared
${WEB_SERVICE_LIBRARY}                 stackql_test_tooling.web_service_keywords
${STACKQL_INTERFACE_LIBRARY}           stackql_test_tooling.StackQLInterfaces
${CLOUD_INTEGRATION_LIBRARY}           stackql_test_tooling.CloudIntegration

*** Settings ***
Library           Process
Library           OperatingSystem 
Variables         ${CORE_LIB_HOME}${/}stackql_context.py    ${CORE_REPOSITORY_ROOT}    ${EXECUTION_PLATFORM}    ${SQL_BACKEND}    ${USE_STACKQL_PREINSTALLED}
...               ${SUNDRY_CONFIG}
Library           Process
Library           OperatingSystem
Library           String
Library           ${STACKQL_INTERFACE_LIBRARY}    ${EXECUTION_PLATFORM}    ${SQL_BACKEND}    ${CONCURRENCY_LIMIT}
Library           ${CLOUD_INTEGRATION_LIBRARY}
Library           ${WEB_SERVICE_LIBRARY}          ${CWD_FOR_EXEC}

*** Keywords ***

Start All Mock Servers
    ${port_dict} =    Create Dictionary    
    ...    oauth_client_credentials_token=${MOCKSERVER_PORT_OAUTH_CLIENT_CREDENTIALS_TOKEN}
    ...    github=${MOCKSERVER_PORT_GITHUB}
    ...    google=${MOCKSERVER_PORT_GOOGLE}
    ...    okta=${MOCKSERVER_PORT_OKTA}
    ...    aws=${MOCKSERVER_PORT_AWS}
    ...    stackql_auth_testing=${MOCKSERVER_PORT_STACKQL_AUTH_TESTING}
    ...    googleadmin=${MOCKSERVER_PORT_GOOGLEADMIN}
    ...    k8s=${MOCKSERVER_PORT_K8S}
    ...    registry=${MOCKSERVER_PORT_REGISTRY}
    ...    azure=${MOCKSERVER_PORT_AZURE}
    ...    sumologic=${MOCKSERVER_PORT_SUMOLOGIC}
    ...    digitalocean=${MOCKSERVER_PORT_DIGITALOCEAN}
    Start All Webservers    port_dict=${port_dict}


Prepare StackQL Environment
    Set Environment Variable    OKTA_SECRET_KEY    ${OKTA_SECRET_STR}
    Set Environment Variable    GITHUB_SECRET_KEY    ${GITHUB_SECRET_STR}
    Set Environment Variable    K8S_SECRET_KEY    ${K8S_SECRET_STR}
    Set Environment Variable    AZ_ACCESS_TOKEN    ${AZURE_SECRET_STR}
    Set Environment Variable    SUMO_CREDS    ${SUMOLOGIC_SECRET_STR}
    Set Environment Variable    DIGITALOCEAN_TOKEN    ${DIGITALOCEAN_SECRET_STR}
    Set Environment Variable    DUMMY_DIGITALOCEAN_USERNAME    ${DUMMY_DIGITALOCEAN_USERNAME_STR}
    Set Environment Variable    DUMMY_DIGITALOCEAN_PASSWORD    ${DUMMY_DIGITALOCEAN_PASSWORD_STR}
    Set Environment Variable    DB_SETUP_SRC    ${DB_SETUP_SRC}
    Set Environment Variable    GOOGLE_APPLICATION_CREDENTIALS    ${GOOGLE_APPLICATION_CREDENTIALS}
    Set Environment Variable    DD_API_KEY    %{DD_API_KEY=myusername}
    Set Environment Variable    DD_APPLICATION_KEY    %{DD_APPLICATION_KEY=mypassword}
    Start All Mock Servers
    Sleep    50s

Stock Stackql Exec Inline Equals Both Streams
    [Arguments]    ${inputStr}    ${outputStr}    ${outputStderrStr}    ${tmpFileTrunk}
    Should Stackql Exec Inline Equal Both Streams
    ...    ${STACKQL_EXE}
    ...    ${OKTA_SECRET_STR}
    ...    ${GITHUB_SECRET_STR}
    ...    ${K8S_SECRET_STR}
    ...    ${REGISTRY_NO_VERIFY_CFG_STR}
    ...    ${AUTH_CFG_STR}
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
