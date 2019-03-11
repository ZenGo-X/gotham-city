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

# Adding utilities for JWT and Cognito auth
ADD gotham-utilities /gotham-utilities
WORKDIR /gotham-utilities/server/cognito
RUN ["npm", "install"]

WORKDIR /

# Rust
ARG CHANNEL="nightly"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${CHANNEL}

# Server
ENV rocket_address=0.0.0.0
ENV rocket_port=8000
ENV db=AWS

EXPOSE 8000
ADD gotham-server /app
WORKDIR /app
RUN ["/root/.cargo/bin/cargo", "update"]
RUN ["/root/.cargo/bin/cargo", "build", "--release"]
CMD ["/root/.cargo/bin/cargo", "run", "--release"]


