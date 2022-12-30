import sys, json, os, boto3, botocore
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from dateutil.relativedelta import *

print("getting REG_ARTIFACT_REPO_BUCKET env var...")
repo_bucket_name = os.getenv('REG_ARTIFACT_REPO_BUCKET')

## TODO incomplete

#
# S3 setup and functions
#

s3_client = boto3.client('s3')

def list_versions(provider):
    print("here")

def download_file(file_name, bucket, object_name):
    print("pushing %s to s3://%s..." % (file_name, bucket))
    try:
        s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        print(e)
        sys.exit(1)

#
# main routine
#        

print("getting REG_TARGET_BRAMCH env var...")
target_branch = os.getenv('REG_TARGET_BRAMCH')

print("getting REG_MAX_VERSIONS env var...")
max_versions = os.getenv('REG_MAX_VERSIONS')

print("getting REG_MAX_AGE_MONTHS env var...")
max_age_months = os.getenv('REG_MAX_AGE_MONTHS')

print("getting PROVIDERS env var...")
providers = json.loads(os.getenv('PROVIDERS'))

all_providers = os.listdir("providers/src")

# get list of updated providers in this build (names only)
updated_providers = []
print("getting updated providers...")
for provider in providers:
    updated_providers.append(provider['provider'])

# pull additional docs from artifact repo needed for deployment
for provider in all_providers:
    local_objects = os.listdir("%s/%s/%s" % (os.getenv('REG_WEBSITE_DIR'), os.getenv('REG_PROVIDER_PATH'), provider))

    print(local_objects)

    print("getting list of objects in the %s bucket..." % (repo_bucket_name))
    objects = []
    for obj in s3_client.list_objects_v2(
        Bucket=repo_bucket_name,
        Prefix="%s/%s" % (os.getenv('REG_PROVIDER_PATH'), provider)
        # Delimiter='string',
        # StartAfter='string'
        )['Contents']:
        objects.append(obj['Key'])

    print(objects)    

    # if provider in updated_providers:
    #     if target_branch == "main":
    #         # get delta versions
    #         print("getting delta versions for %s..." % (provider))
    # else:
    #     if target_branch == "main":
    #         # get REG_MAX_VERSIONS for provider
    #         print("getting %s latest versions for %s..." % (max_versions, provider))
    #     else:
    #         print("getting latest version for %s..." % (provider))