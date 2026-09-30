"""
Shared validation helpers for the registry build pipeline.

Everything under providers/src is contributor controlled: directory names,
file names and file types all arrive via pull requests, and the post merge
run of .github/workflows/main.yml signs and publishes that content with the
registry signing key in its environment. Before any contributor supplied
name is interpolated into a path, passed to a tool, signed, packaged or
written to $GITHUB_ENV it is checked here.
"""

import os
import re
import stat
import sys
import uuid

# provider dirs, version dirs, service files and artifact file names: must
# start with an alphanumeric character or '_' and contain only alphanumerics,
# '.', '_' and '-'. This rules out shell metacharacters, quotes, whitespace,
# path separators, '.' / '..', hidden files and leading '-'.
# (matched with fullmatch: unlike '$', it does not accept a trailing newline)
SAFE_NAME_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._-]*')

# environment variable names written to $GITHUB_ENV
ENV_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')

PROVIDERS_SRC_ROOT = os.path.join('providers', 'src')


def fail(message):
    print("ERROR: %s" % (message), file=sys.stderr)
    sys.exit(1)


def is_safe_name(name):
    return isinstance(name, str) and SAFE_NAME_RE.fullmatch(name) is not None


def require_safe_name(name, what):
    if not is_safe_name(name):
        fail("invalid %s %r: must match %s" % (what, name, SAFE_NAME_RE.pattern))
    return name


def _is_within(path, root):
    real_root = os.path.realpath(root)
    real_path = os.path.realpath(path)
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def _lstat(path):
    try:
        return os.lstat(path)
    except OSError as e:
        fail("cannot stat %s: %s" % (path, e))


def require_regular_file(path, root):
    """path must be a regular file (not a symlink, device, fifo, ...) that
    resolves to a location inside root"""
    st = _lstat(path)
    if stat.S_ISLNK(st.st_mode):
        fail("%s is a symbolic link; symlinks are not permitted under %s" % (path, PROVIDERS_SRC_ROOT))
    if not stat.S_ISREG(st.st_mode):
        fail("%s is not a regular file" % (path))
    if not _is_within(path, root):
        fail("%s resolves outside %s" % (path, root))
    return path


def require_real_dir(path, root):
    """path must be a directory (not a symlink to one) inside root"""
    st = _lstat(path)
    if stat.S_ISLNK(st.st_mode):
        fail("%s is a symbolic link; symlinks are not permitted under %s" % (path, PROVIDERS_SRC_ROOT))
    if not stat.S_ISDIR(st.st_mode):
        fail("%s is not a directory" % (path))
    if not _is_within(path, root):
        fail("%s resolves outside %s" % (path, root))
    return path


def validate_provider_source_tree(provider_dir, source_version, repo_root='.'):
    """
    Validate providers/src/<provider_dir>/<source_version> on disk:

        providers/src/<provider_dir>/<source_version>/provider.yaml    regular file
        providers/src/<provider_dir>/<source_version>/services/        directory
        providers/src/<provider_dir>/<source_version>/services/<svc>   regular files

    Every name is checked against SAFE_NAME_RE, no path component may be a
    symlink, nothing may resolve outside the provider version directory and
    no other entries are permitted. Returns the sorted list of service file
    names.
    """
    require_safe_name(provider_dir, 'provider directory name')
    require_safe_name(source_version, 'provider version')

    # walk down one component at a time so a symlinked parent is caught too
    providers_root = require_real_dir(os.path.join(repo_root, 'providers'), repo_root)
    src_root = require_real_dir(os.path.join(providers_root, 'src'), providers_root)
    provider_root = require_real_dir(os.path.join(src_root, provider_dir), src_root)
    version_root = require_real_dir(os.path.join(provider_root, source_version), provider_root)

    require_regular_file(os.path.join(version_root, 'provider.yaml'), version_root)

    services_dir = require_real_dir(os.path.join(version_root, 'services'), version_root)

    service_files = sorted(os.listdir(services_dir))
    for service_file in service_files:
        require_safe_name(service_file, 'service file name')
        require_regular_file(os.path.join(services_dir, service_file), services_dir)

    for entry in os.listdir(version_root):
        if entry not in ('provider.yaml', 'services'):
            fail("unexpected entry %r in %s; only provider.yaml and services/ are permitted" % (entry, version_root))

    return service_files


def parse_artifact_key(key, provider_path):
    """
    Validate an artifact repo object key of the form

        <provider_path>/<provider_dir>/<file>

    and return (provider_dir, file). Keys are joined onto local paths before
    download, so anything else (extra or missing segments, '..', empty or
    unsafe names) is rejected.
    """
    prefix = provider_path.rstrip('/') + '/'
    if not key.startswith(prefix):
        fail("artifact key %r is not under %s" % (key, prefix))
    parts = key[len(prefix):].split('/')
    if len(parts) != 2:
        fail("artifact key %r does not have the form %s<provider>/<file>" % (key, prefix))
    provider_dir = require_safe_name(parts[0], 'provider directory name')
    file_name = require_safe_name(parts[1], 'artifact file name')
    return provider_dir, file_name


def write_github_env(name, value):
    """
    Append NAME=VALUE to $GITHUB_ENV using the heredoc form the runner
    understands, the same way @actions/core exportVariable does. The value
    is written directly to the file; nothing goes through a shell.
    """
    env_file = os.getenv('GITHUB_ENV')
    if not env_file:
        fail("GITHUB_ENV is not set")
    if not ENV_NAME_RE.fullmatch(name):
        fail("invalid environment variable name %r" % (name))
    value = str(value)
    delimiter = "ghadelimiter_%s" % (uuid.uuid4())
    if delimiter in value:
        fail("unexpected delimiter collision writing %s" % (name))
    with open(env_file, 'a', encoding='utf-8') as f:
        f.write("%s<<%s\n%s\n%s\n" % (name, delimiter, value, delimiter))
