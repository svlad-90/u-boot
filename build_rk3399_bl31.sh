#!/bin/bash

# Currently trusted-firmware-a does not build with modern clang so it
# must be built with GCC. However, the GCC in Android is too old (and
# deprecated anyway) so we must use Debian's compilers. Because these
# toolchains are not installed on the builders, we must have a way
# to regenerate the binary offline.

set -e

which aarch64-linux-gnu-gcc >/dev/null || \
  (echo "Install gcc-aarch64-linux-gnu!" && exit 1)
which arm-none-eabi-gcc >/dev/null || \
  (echo "Install gcc-arm-none-eabi!" && exit 2)

SCRIPT_DIR=$(dirname $0)
. "$SCRIPT_DIR/build.config.common"

ROOT_DIR=$(realpath "$SCRIPT_DIR/..")
mkdir -p "$ROOT_DIR/out/$BRANCH"
cd "$ROOT_DIR/external/arm-trusted-firmware/"

BUILD_BASE="$ROOT_DIR/out/$BRANCH"
export CROSS_COMPILE=aarch64-linux-gnu-
make PLAT=rk3399 DEBUG=0 ERROR_DEPRECATED=1 BUILD_BASE=$BUILD_BASE distclean
make PLAT=rk3399 DEBUG=0 ERROR_DEPRECATED=1 BUILD_BASE=$BUILD_BASE bl31

cd - >/dev/null
cp -v "$BUILD_BASE/rk3399/release/bl31/bl31.elf" "$SCRIPT_DIR/bl31.elf"
