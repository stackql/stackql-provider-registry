import json, sys, os, subprocess

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
    source_version = provider["source_version"]
    target_version = provider["target_version"]
    
    src_root_dir = "providers/src/%s/%s" % (provider_name, source_version)
    src_services_dir = "%s/services" % (src_root_dir)

    tgt_root_dir = "signed/providers/src/%s/%s" % (provider_name, target_version)    
    tgt_services_dir = "%s/services" % (tgt_root_dir)
    
    if not os.path.exists(tgt_services_dir):
        os.makedirs(tgt_services_dir)

    srcfile = "%s/provider.yaml" % (src_root_dir)
    tgtfile = "%s/provider.yaml.sig" % (tgt_root_dir)

    sign_file(srcfile, tgtfile)
    os.system("cp %s/provider.yaml %s/provider.yaml" % (src_root_dir, tgt_root_dir))

    # sign each service
    for service_file in os.listdir(src_services_dir):
        srcfile = "%s/%s" % (src_services_dir, service_file)
        tgtfile = "%s/%s.sig" % (tgt_services_dir, service_file)
        sign_file(srcfile, tgtfile)        
        os.system("cp %s/%s %s/%s" % (src_services_dir, service_file, tgt_services_dir, service_file))

    
