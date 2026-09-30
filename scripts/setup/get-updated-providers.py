import os, json, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from common.provider_tree import fail, require_safe_name, validate_provider_source_tree, write_github_env

print("getting REG_VERSION env var...")

target_version = require_safe_name(os.getenv('REG_VERSION'), 'REG_VERSION')

#
# paths in diff.txt come straight from the pull request author. only the
# following layouts are accepted, and every component must be a safe name
# (see scripts/common/provider_tree.py):
#
#   providers/src/<provider_dir>/<version>/provider.yaml
#   providers/src/<provider_dir>/<version>/services/<service_file>
#

def parse_provider_path(path):
    parts = path.split('/')
    if len(parts) == 5 and parts[4] == 'provider.yaml':
        pass
    elif len(parts) == 6 and parts[4] == 'services':
        require_safe_name(parts[5], 'service file name')
    else:
        fail("unexpected path under providers/src: %r (expected <provider>/<version>/provider.yaml or <provider>/<version>/services/<file>)" % (path))
    provider_dir = require_safe_name(parts[2], 'provider directory name')
    source_version = require_safe_name(parts[3], 'provider version')
    return provider_dir, source_version

print("finding updated providers...")

with open('diff.txt', 'r') as f:
    lines = f.readlines()
    updates = []
    all_provider_versions = []
    for line in lines:
        line = line.rstrip('\r\n')
        if not line.strip():
            continue
        fields = line.split('\t')
        action = fields[0]
        # renames and copies (R/C) list the old and new path; the new path is the one on disk
        path = fields[-1]
        if path.startswith('"'):
            # git C-quotes paths containing control, non-ASCII, quote or backslash
            # characters; such names are never valid provider paths
            if 'providers/src/' in path:
                fail("provider path contains characters that are not permitted: %s" % (path))
            continue
        if path in ('providers', 'providers/src'):
            # only appears in a name-status diff if the directory was replaced by a file or symlink
            fail("%s must be a directory" % (path))
        if path.startswith('providers/src/'):
            provider = {}
            provider_dir, source_version = parse_provider_path(path)
            if provider_dir == 'googleapis.com':
                provider_name = 'google'
            else:
                provider_name = provider_dir
            if source_version != 'v00.00.00000':
                print('ERROR: baseline version for providers must be v00.00.00000')
                sys.exit(1)
            all_provider_versions.append(json.dumps({ 'provider' : provider_name, 'provider_dir': provider_dir, 'source_version': source_version, 'target_version': target_version}))
            provider['provider'] = provider_name
            provider['provider_dir'] = provider_dir
            provider['source_version'] = source_version
            provider['target_version'] = target_version
            provider['action'] = action
            provider['path'] = path
            updates.append(provider)
            if provider_name == 'awscc':
                # add faux provider update for aws, as aws is a dependency of awscc
                all_provider_versions.append(json.dumps({ 'provider' : 'aws', 'provider_dir': 'aws', 'source_version': 'v00.00.00000', 'target_version': target_version}))
                provider['provider'] = 'aws'
                provider['provider_dir'] = 'aws'
                provider['source_version'] = 'v00.00.00000'
                provider['target_version'] = target_version
                provider['action'] = 'M'
                provider['path'] = 'providers/src/awscc/v00.00.00000/provider.yaml'

    # convert to set to remove duplicates
    providers = []
    for provider in list(set(all_provider_versions)):
        providers.append(json.loads(provider))

    num_providers = len(providers)

    print("%s providers updated" % (str(num_providers)))
    print("providers updated : %s" % (providers))

    # refuse symlinks, non-regular files, unexpected entries and unsafe names in
    # the checked out tree now, before any later step reads it with secrets in
    # the environment
    for provider in providers:
        print("validating providers/src/%s/%s..." % (provider['provider_dir'], provider['source_version']))
        validate_provider_source_tree(provider['provider_dir'], provider['source_version'])

    if num_providers > 0:
        print("setting environment variables...")

        # write provider/version json to the PROVIDERS env var
        write_github_env('PROVIDERS', json.dumps(providers))

        # populate NUM_PROVIDERS env var
        write_github_env('NUM_PROVIDERS', str(num_providers))

        print("writing output files...")

        # write list of providers to a text file
        with open('providers.txt', 'w') as f:
            for provider in providers:
                print(provider['provider'])
                f.write("%s\n" % (provider['provider']))

        # write list of provider dirs to a text file
        with open('provider_dirs.txt', 'w') as f:
            for provider in providers:
                f.write("%s\n" % (provider['provider_dir']))

        # write all provider updates to file
        with open('updates.json', 'w') as f:
            f.write(json.dumps(updates))

    else:

        # write empty provider/version json to the PROVIDERS env var
        write_github_env('PROVIDERS', json.dumps(providers))

        # set NUM_PROVIDERS env var == 0
        write_github_env('NUM_PROVIDERS', str(num_providers))
