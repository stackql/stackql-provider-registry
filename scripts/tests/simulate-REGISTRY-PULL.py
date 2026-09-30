import json, tarfile, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from common.provider_tree import require_safe_name

print("getting PROVIDERS env var...")
providers = json.loads(os.getenv('PROVIDERS'))

print("getting REG_TARGET_BRANCH env var...")
target_branch = require_safe_name(os.getenv('REG_TARGET_BRANCH'), 'REG_TARGET_BRANCH')

for provider in providers:
    provider_name = provider["provider"]
    provider_dir = require_safe_name(provider["provider_dir"], 'provider directory name')
    version = require_safe_name(provider["target_version"], 'target version')

    if target_branch == 'main':
        key = "%s/%s/%s.tgz" % (os.getenv('REG_PROVIDER_PATH'), provider_dir, version)
    else:
        key = "%s/%s/%s-%s.tgz" % (os.getenv('REG_PROVIDER_PATH'), provider_dir, version, target_branch)

    archive = "%s/%s" % (os.getenv('REG_WEBSITE_DIR'), key)
    print("extracting %s" % (archive))

    # the 'data' filter (PEP 706) refuses absolute paths, path traversal, links
    # pointing outside the destination and special files
    with tarfile.open(archive) as file:
        file.extractall("provider-tests/src/%s" % (provider_dir), filter='data')
