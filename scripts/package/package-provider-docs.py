import json, os, tarfile, subprocess, sys, shutil

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from common.provider_tree import require_safe_name

def tardirectory(srcdir, arcname, dir2tar):
    p = subprocess.Popen(["tar", "-czf", arcname, dir2tar], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=srcdir)
    p.wait()
    err = p.stderr.read().decode()
    if err:
        print("ERROR: %s" % (err))
        sys.exit(1)

print("getting PROVIDERS env var...")
providers = json.loads(os.getenv('PROVIDERS'))

print("getting REG_TARGET_BRANCH env var...")
target_branch = require_safe_name(os.getenv('REG_TARGET_BRANCH'), 'REG_TARGET_BRANCH')

for provider in providers:
    provider_name = provider["provider"]
    provider_dir = require_safe_name(provider["provider_dir"], 'provider directory name')
    version = require_safe_name(provider["target_version"], 'target version')

    if target_branch == 'main':
        key = "%s.tgz" % (version)
    else:
        key = "%s-%s.tgz" % (version, target_branch)

    print("creating tar file for %s/%s as %s" % (provider_name, version, key))
    tardirectory("signed/providers/src/%s" % (provider_dir),"%s" % (key), "%s" % (version))

    # move package to target directory
    src = "signed/providers/src/%s/%s" % (provider_dir, key)
    dest = "%s/%s/%s/%s" % (os.getenv('REG_WEBSITE_DIR'), os.getenv('REG_PROVIDER_PATH'), provider_dir, key)

    print("moving %s to %s" % (src, dest))
    shutil.move(src, dest)
