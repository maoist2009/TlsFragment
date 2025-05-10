#!/usr/bin/env bash
set -eux pipefail

ROOT=$(realpath $(dirname "$0")/../..)

[[ -d "$ROOT"/build/android ]] || mkdir -p "$ROOT"/build/android

chown -R root build/android

(
  cd "$ROOT"/build/android
  export HOME="$PWD"
  export GRADLE_USER_HOME="$PWD"/.gradle
  export ANDROID_USER_HOME="$PWD"/.android

  python3 -m venv venv
  source venv/bin/activate

  python3 -m pip install --upgrade pip
  python3 -m pip install --force-reinstall -r "$ROOT"/tools/build/requirements.txt
  python3 -m pip install --force-reinstall -r "$ROOT"/tools/build/requirements_build_android.txt

  # Remove APK if exists
  rm -rf bin

  # Build
  (
    cp "$ROOT"/tools/build/buildozer.spec .
    yes| python3 -m buildozer android debug
  )
)

# change permissions to allow cache copying
find build/android -type d -exec chmod 755 {} \;
find build/android -type f -exec chmod 644 {} \;

# sanity check
PACKAGE="$ROOT"/build/android/bin/

if ls "$PACKAGE"; then
    echo Successfully built.
else
    echo Error: "$PACKAGE" doesn\'t exist >&2; exit 1;
fi
