import json, sys, os, subprocess, shutil

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from common.provider_tree import require_safe_name, validate_provider_source_tree

sign_file_script = "scripts/package/sign-file.sh"

def sign_file(srcfile, tgtfile):
    p = subprocess.Popen(["sh", sign_file_script, srcfile, tgtfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    err = p.stderr.read().decode()
    if err:
        print("ERROR: %s" % (err))
        sys.exit(1)
    else:
        print("SUCCESS: %s" % (p.stdout.read().decode()))

signing_version = os.getenv('SIGNING_VERSION')

print("signing with %s keys and certs" % (signing_version))

os.environ['PUBLIC_KEY_FILE'] = "%s-public-key.pem" % (signing_version)
os.environ['CERT_FILE'] = "%s-cert.pem" % (signing_version)

print("getting PROVIDERS env var...")
providers = json.loads(os.getenv('PROVIDERS'))

# Add the signature to each provider
for provider in providers:
    provider_name = provider["provider"]
    provider_dir = require_safe_name(provider["provider_dir"], 'provider directory name')
    source_version = require_safe_name(provider["source_version"], 'provider version')
    target_version = require_safe_name(provider["target_version"], 'target version')

    # this step runs with the signing key in its environment: refuse symlinks,
    # non-regular files, unexpected entries and unsafe names before any file
    # under providers/src is opened
    service_files = validate_provider_source_tree(provider_dir, source_version)

    src_root_dir = "providers/src/%s/%s" % (provider_dir, source_version)
    src_services_dir = "%s/services" % (src_root_dir)

    tgt_root_dir = "signed/providers/src/%s/%s" % (provider_dir, target_version)
    tgt_services_dir = "%s/services" % (tgt_root_dir)

    if not os.path.exists(tgt_services_dir):
        os.makedirs(tgt_services_dir)

    srcfile = "%s/provider.yaml" % (src_root_dir)
    tgtfile = "%s/provider.yaml.sig" % (tgt_root_dir)

    sign_file(srcfile, tgtfile)
    shutil.copyfile(srcfile, "%s/provider.yaml" % (tgt_root_dir))

    # sign each service
    for service_file in service_files:
        srcfile = "%s/%s" % (src_services_dir, service_file)
        tgtfile = "%s/%s.sig" % (tgt_services_dir, service_file)
        sign_file(srcfile, tgtfile)
        shutil.copyfile(srcfile, "%s/%s" % (tgt_services_dir, service_file))
