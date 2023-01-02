import sys, json, os, boto3, botocore
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

#
# get env vars
#

print("getting REG_TARGET_BRAMCH env var...")
target_branch = os.getenv('REG_TARGET_BRAMCH')

print("getting REG_SHA env var...")
commit_sha = os.getenv('REG_SHA')

print("getting REG_COMMIT_SHA env var...")
long_commit_sha = os.getenv('REG_COMMIT_SHA')

print("getting REG_COMMIT_DATETIME env var...")
date_published = os.getenv('REG_COMMIT_DATETIME')

print("getting REG_ARTIFACT_REPO_BUCKET env var...")
repo_bucket_name = os.getenv('REG_ARTIFACT_REPO_BUCKET')

print("getting AWS_DEFAULT_REGION env var...")
aws_region = os.getenv('AWS_DEFAULT_REGION')

print("getting PROVIDERS env var...")
providers = json.loads(os.getenv('PROVIDERS'))

#
# S3 setup and functions
#

s3 = boto3.resource('s3')
s3_client = boto3.client('s3')

repo_bucket = s3.Bucket(repo_bucket_name)

def upload_file(file_name, bucket, object_name, provider, target_branch):
    print("pushing %s to s3://%s..." % (file_name, bucket))
    try:
        s3_client.upload_file(file_name, bucket, object_name)
        # tag object with commit sha and date published
        s3_client.put_object_tagging(
            Bucket=bucket,
            Key=object_name,
            Tagging={
                'TagSet': [
                    {
                        'Key': 'provider',
                        'Value': provider
                    },
                    {
                        'Key': 'targetBranch',
                        'Value': target_branch
                    },                    
                    {
                        'Key': 'commitSha',
                        'Value': long_commit_sha
                    },
                    {
                        'Key': 'datePublished',
                        'Value': date_published
                    },
                ]
            }
        )
    except ClientError as e:
        print(e)
        sys.exit(1)


#
# main routine
#

print("getting list of objects in the %s bucket..." % (repo_bucket_name))
objects = []
for obj in repo_bucket.objects.all():
    objects.append(obj.key)

print("getting updated providers...")
for provider in providers:
    provider_name = provider['provider']
    version = provider['target_version']

    print("processing %s (%s) version %s..." % (provider_name, target_branch, version))

    # 
    # push artifacts to s3
    #

    if target_branch == 'main':
        key = "%s/%s/%s.tgz" % (os.getenv('REG_PROVIDER_PATH'), provider_name, version)
    else:
        key = "%s/%s/%s-%s.tgz" % (os.getenv('REG_PROVIDER_PATH'), provider_name, version, target_branch)

    if target_branch == 'main':
        print("checking if %s exists in %s..." % (key, repo_bucket_name))
        if key in objects:
            print("ERROR: %s exists in the %s bucket" % (key, repo_bucket_name))
            sys.exit(1)
    else:
        print("skipping existing check as target branch is %s" % (target_branch))

    upload_file("%s/%s" % (os.getenv('REG_WEBSITE_DIR'), key), repo_bucket_name, key, provider_name, target_branch)    
