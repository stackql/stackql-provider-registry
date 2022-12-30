import json, os, tarfile

def tardirectory(path, name):
   with tarfile.open(name, "w:gz") as tarhandle:
      for root, dirs, files in os.walk(path):
         for f in files:
            tarhandle.add(os.path.join(root, f), arcname="%s/%s" % (os.path.relpath(root, path), f))

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

    print("creating tar file for %s/%s as %s" % (provider_name, version, key))
    tardirectory("signed/providers/src/%s/%s" % (provider_name, version),"%s/%s" % (os.getenv('REG_WEBSITE_DIR'), key))
