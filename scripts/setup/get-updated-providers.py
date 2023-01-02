import os, json, sys

print("getting REG_VERSION env var...")

target_version = os.getenv('REG_VERSION')

print("finding updated providers...")

with open('diff.txt', 'r') as f:
    lines = f.readlines()
    updates = []
    all_provider_versions = []
    for line in lines:
        fields = line.split('\t')
        action = fields[0]
        path = fields[1]
        if path.startswith('providers/src/'):
            provider = {}
            provider_dir = path.split('/')[2]
            if provider_dir == 'googleapis.com':
                provider_name = 'google'
            else:
                provider_name = provider_dir
            source_version = path.split('/')[3]
            if source_version != 'v00.00.00000':
                print('ERROR: baseline version for providers must be v00.00.00000')
                sys.exit(1)
            all_provider_versions.append(json.dumps({ 'provider' : provider_name, 'source_version': source_version, 'target_version': target_version}))
            provider['provider'] = provider_name
            provider['provider_dir'] = provider_dir
            provider['source_version'] = source_version
            provider['target_version'] = target_version
            provider['action'] = action
            provider['path'] = path.rstrip('\n')
            updates.append(provider)

    # convert to set to remove duplicates
    providers = []
    for provider in list(set(all_provider_versions)):
        providers.append(json.loads(provider))

    num_providers = len(providers)

    print("%s providers updated" % (str(num_providers)))
    print("providers updated : %s" % (providers))

    if num_providers > 0:
        print("setting environment variables...")
        
        # write provider/version json to the PROVIDERS env var
        os.system("echo '%s' >> $GITHUB_ENV" % ("PROVIDERS=" + json.dumps(providers)))

        # populate NUM_PROVIDERS env var
        os.system("echo ""%s"" >> $GITHUB_ENV" % ("NUM_PROVIDERS=" + str(num_providers)))

        print("writing output files...")

        # write list of providers to a text file
        with open('providers.txt', 'w') as f:
            for provider in providers:
                f.write("%s\n" % (provider['provider_dir']))

        # write all provider updates to file
        with open('updates.json', 'w') as f:
            f.write(json.dumps(updates))

