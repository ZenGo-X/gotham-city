#!/usr/bin/env bash
set -x

pushd .
cd "$(dirname "$0")"
## BUILD AARCH64

if [ -z $(rustup toolchain list |  grep ios) ]; then
brew install ninja cmake
git clone https://github.com/getditto/rust-bitcode.git
cd rust-bitcode
./build.sh
./install.sh
fi

IOS_TOOLCHAIN=$(rustup toolchain list | grep ios)
cargo +${IOS_TOOLCHAIN} build --target aarch64-apple-ios --release --lib

## BUILD INTEL
cargo build --target x86_64-apple-ios --release --lib

lipo -create -output libclient_lib.a ../../../target/{aarch64-apple-ios,x86_64-apple-ios}/release/libclient_lib.a 

popd .
