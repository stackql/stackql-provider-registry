
# Test Developer Guide


## Local Setup

You will need to have these on your machine:

- `python` at a version `>= 3.11`.  To see if it is already present and what version, type this in a terminal `python --version`.  Hopefully you will see something like `Python 3.13.2` appear.  You can also try `python3 --version`; although if only this latter works then you will want to set up an alias (outside scope of this doc).  If it is not present at all, then install it per [python downloads page](https://www.python.org/downloads/)
- `go` at a version `>= 1.19`.  To see if it is already present and what version, type this in a terminal `go version`.  Hopefully you will see something like `go version go1.22.0 darwin/amd64` appear.  If it is missing or some inadequate verison, then install it per [the official go install page](https://go.dev/doc/install).
- `openssl`, prefererable version 3 sometging, although earlier versions will probably work.  To see if it is already present and what version, type this in a terminal `openssl --version`.  Hopefully you will see something like `OpenSSL 3.4.1 11 Feb 2025 (Library: OpenSSL 3.4.1 11 Feb 2025)` appear.   If not present, then, on Mac, use [homebrew](https://brew.sh/) to install it with `brew install openssl`.

In addition, you will need shell scripts with exported credentials in the files (relative to repository root):

- `scripts/sec/sec-ro-stackql.sh`.
- `scripts/sec/sec-rw-stackql.sh`.

Then, once all this is in place, test setup can be done as a "once-off" (run again when you want to update dependencies) with:

```bash

scripts/local/ci/01-gather.sh

scripts/local/ci/02-setup.sh

```

All sorts of stuff will happen here and may take a little while.

Then, to run readonly tests locally: `scripts/local/ci/03-run-live-readonly.sh`.

To run readwrite tests locally (more dangerous): `scripts/local/ci/04-run-live-readwrite.sh`.


You can now develop new test cases.  Once they are working locally, you can test them remotely (once you are in the appropriate `github` group) by pushing a `git` tag that begins
with `robot`, `regression`, or `integration`.


