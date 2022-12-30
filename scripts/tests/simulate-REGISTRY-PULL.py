import json, tarfile, os

print("getting PROVIDERS env var...")
providers = json.loads(os.getenv('PROVIDERS'))

print("getting REG_TARGET_BRAMCH env var...")
target_branch = os.getenv('REG_TARGET_BRAMCH')

for provider in providers:
    provider_name = provider["provider"]
    version = provider["target_version"]

    if target_branch == 'main':
        key = "%s/%s/%s.tgz" % (os.getenv('REG_PROVIDER_PATH'), provider_name, version)
    else:
        key = "%s/%s/%s-%s.tgz" % (os.getenv('REG_PROVIDER_PATH'), provider_name, version, target_branch)

    archive = "%s/%s" % (os.getenv('REG_WEBSITE_DIR'), key)
    print("extracting %s" % (archive))
  
    file = tarfile.open(archive)
    file.extractall("provider-tests/src/%s/%s" % (provider_name, version))
    file.close()