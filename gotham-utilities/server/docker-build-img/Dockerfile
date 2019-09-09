FROM ubuntu:xenial
LABEL maintainer="g.benattar@gmail.com"
LABEL description="This is the build stage for Gotham server"

RUN apt-get update && apt-get install -y \
    build-essential \
    make \
    g++ \
    curl \
    clang \
    libgmp3-dev \
    libssl-dev \
    pkg-config \
    npm

RUN curl -sL https://deb.nodesource.com/setup_11.x | bash -
RUN apt-get install -y nodejs

ADD . /

WORKDIR /gotham-utilities/server/cognito
RUN ["npm", "install"]

# Rust
ARG CHANNEL="nightly"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2019-07-10

ENV rocket_address=0.0.0.0
ENV rocket_port=8000

EXPOSE 8000
WORKDIR /gotham-server
RUN ["/root/.cargo/bin/cargo", "build", "--release"]


WORKDIR /integration-tests
RUN ["/root/.cargo/bin/cargo", "test", "--release", "--", "--nocapture"]

# Server
ENV db=AWS
WORKDIR /gotham-server
CMD ["/root/.cargo/bin/cargo", "run", "--release"]


