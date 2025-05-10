#!/usr/bin/env bash
set -euxo pipefail

# Debian 8 has outdated certificates
export GIT_SSL_NO_VERIFY=1

# Old git fails with "unable to look up current user in the passwd file: no such user"
export GIT_COMMITTER_NAME="Jenkins"
export GIT_COMMITTER_EMAIL="ci@test.com"

# Build
xvfb-run -s "-screen 0 1280x1024x24" /bin/bash tools/build/build_linux.sh

# Rename executable
mv build/linux/dist/helloworld.run \
   build/linux/dist/helloworld-linux-x86_64.run
