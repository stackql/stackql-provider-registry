import os, json, sys

from fileinput import FileInput

print("getting PROVIDERS env var...")

providers = json.loads(os.getenv('PROVIDERS'))

# update versions globally in the provider.yaml for each provider
for provider in providers:
    provider_name = provider["provider"]
    provider_dir = provider["provider_dir"]
    source_version = provider["source_version"]
    target_version = provider["target_version"]

    print("updating %s from %s to %s" % (provider_name, source_version, target_version))

    # update the provider.yaml
    provider_yaml = "providers/src/%s/%s/provider.yaml" % (provider_dir, source_version)
    with FileInput(files=[provider_yaml], inplace=True) as f:
        for line in f:
            op = line.replace(source_version, target_version)
            print(op, end='')
      