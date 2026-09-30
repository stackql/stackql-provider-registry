import os, json, sys

from fileinput import FileInput

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from common.provider_tree import require_safe_name, validate_provider_source_tree

print("getting PROVIDERS env var...")

providers = json.loads(os.getenv('PROVIDERS'))

# update versions globally in the provider.yaml for each provider
for provider in providers:
    provider_name = provider["provider"]
    provider_dir = require_safe_name(provider["provider_dir"], 'provider directory name')
    source_version = require_safe_name(provider["source_version"], 'provider version')
    target_version = require_safe_name(provider["target_version"], 'target version')

    # FileInput(inplace=True) follows symlinks; refuse anything that is not a
    # regular file inside the provider tree before rewriting
    validate_provider_source_tree(provider_dir, source_version)

    print("updating %s from %s to %s" % (provider_name, source_version, target_version))

    # update the provider.yaml
    provider_yaml = "providers/src/%s/%s/provider.yaml" % (provider_dir, source_version)
    with FileInput(files=[provider_yaml], inplace=True) as f:
        for line in f:
            op = line.replace(source_version, target_version)
            print(op, end='')
