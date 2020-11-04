#!/usr/bin/env bash
export ANDROID_NDK_HOME="/Users/jeremy/Library/Android/sdk/ndk/20.0.5594570"
export OPENSSL_DIR="/Users/jeremy/kzen/openssl-android/output"
export OPENSSL_LIB_DIR="$OPENSSL_DIR/lib/android-arm64"
export OPENSSL_INCLUDE_DIR="$OPENSSL_DIR/include"
export CFLAGS="-L/Users/jeremy/kzen/openssl-android/output/lib/android-arm64 -I/Users/jeremy/kzen/openssl-android/output/include"
export CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android23-clang"
export CXX="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android23-clang++"
export AR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android-ar"
cargo build --target aarch64-linux-android --release
# export CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7-linux-androideabi23-clang"
# export CXX="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7-linux-androideabi23-clang++"
# export AR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7-linux-androideabi-ar"
# cargo build --target armv7-linux-androideabi --release
# export CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android23-clang"
# export CXX="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android23-clang++"
# export AR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android-ar"
# cargo build --target i686-linux-android --release