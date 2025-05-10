#!/usr/bin/env bash
set -euxo pipefail

ROOT=$(realpath $(dirname "$0")/../..)

[[ -d "$ROOT"/build/linux ]] \
  || mkdir -p "$ROOT"/build/linux

(
  cd "$ROOT"/build/linux
  export HOME="$PWD"

  python3 -m venv venv
  source venv/bin/activate

  python3 -m pip install --upgrade pip
  python3 -m pip install -r "$ROOT"/tools/build/requirements.txt \
                         -r "$ROOT"/tools/build/requirements_build_linux.txt

  # remove PyInstaller's dist directory if exists
  rm -rf dist

  python3 -m PyInstaller --clean "$ROOT"/tools/build/helloworld.linux.onefile.spec
)

# sanity check
PACKAGE="$ROOT"/build/linux/dist/helloworld.run
[[ -f "$PACKAGE" ]] \
  || { echo Error: "$PACKAGE" doesn\'t exist >&2; exit 1; }

echo Successfully built "$PACKAGE"
