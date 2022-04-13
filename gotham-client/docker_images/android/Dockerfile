# syntax = docker/dockerfile:1.2
FROM rust:latest
ENV GMP_VERSION=6.2.1
ENV NDK_VERSION=24
ENV MIN_SDK_VERSION=31
ENV ANDROID_NDK_HOME=/android-ndk/
ENV PATH="/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/:${PATH}"
ENV OPENSSL_VERSION=1.1.1n
ENV TARGET_CXXFLAGS=-mno-outline-atomics
ENV PKG_CONFIG_SYSROOT_DIR="${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot"
RUN apt update
RUN 	wget https://dl.google.com/android/repository/android-ndk-r${NDK_VERSION}-linux.zip && \
	unzip android-ndk-r*-linux.zip && \
	rm android-ndk-r*-linux.zip && \
	mv android-ndk-r* android-ndk && \
	git clone https://github.com/ZenGo-X/gotham-city.git && \
	cd gotham-city && git checkout server_fix && \
	rustup install nightly && \
	rustup default nightly && \
	rustup target add \
    		aarch64-linux-android \
    		armv7-linux-androideabi \
    		x86_64-linux-android \
    		i686-linux-android && \
	rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu && \
	cargo install cargo-ndk

# libGMP

RUN 	wget https://gmplib.org/download/gmp/gmp-${GMP_VERSION}.tar.lz && \
	apt install lzip && \
	tar -xvf ./gmp-*.tar.lz && \
	rm  gmp-*.tar.lz && \
	mv gmp-* gmp && \
	cd /gmp && \
	mkdir build && \
	cd build && \
	for i in armv7a-linux-androideabi aarch64-linux-android x86_64-linux-android; do \
		mkdir $i && \
		cd $i && \
		../../configure --host=${i}${MIN_SDK_VERSION} CC=${i}${MIN_SDK_VERSION}-clang && \
		 make -j 32 && \
		cd .. ;\
	done && \
	cd /

# OPENSSL

RUN 	wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz && \
	tar -xvf openssl-${OPENSSL_VERSION}.tar.gz && \
	rm openssl-${OPENSSL_VERSION}.tar.gz && \
	mv openssl-${OPENSSL_VERSION} openssl && \
	mkdir /openssl/build && \
	cd /openssl/build/ && \
	for i in android-arm64 android-arm android-x86_64; do \
		mkdir $i && \
		cd $i && \
		../../Configure $i && \
		make -j 32 && \
		cd .. ;\
	done && \
	cd /

# COPY EVERY LIB into sysroot...
RUN 	cp -r /openssl/include/* ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/ && \
	cp -r /openssl/build/android-arm64/include/* ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/ && \
	cp /openssl/build/android-arm64/libssl.so ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android && \
	cp /openssl/build/android-arm64/libcrypto.so ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android && \
	cp /openssl/build/android-arm/libssl.so ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/ && \
	cp /openssl/build/android-arm/libcrypto.so ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/ && \
	cp /openssl/build/android-x86_64/libssl.so ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/ && \
	cp /openssl/build/android-x86_64/libcrypto.so ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/ && \
	cp /gmp/build/aarch64-linux-android/.libs/libgmp.so ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/ && \
	cp /gmp/build/armv7a-linux-androideabi/.libs/libgmp.so ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/ && \
	cp /gmp/build/x86_64-linux-android/.libs/libgmp.so ${ANDROID_NDK_HOME}toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/

# compile
RUN 	cd /gotham-city/gotham-client && cargo +nightly ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ./jniLibs_debug build -Zbuild-std && \
	cd /gotham-city/gotham-client && cargo +nightly ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ./jniLibs build --release -Zbuild-std
