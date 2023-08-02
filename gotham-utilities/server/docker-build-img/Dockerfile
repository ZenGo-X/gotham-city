FROM rust:bullseye
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

RUN curl -fsSL https://deb.nodesource.com/setup_14.x | bash -
RUN apt-get install -y nodejs

ADD . /

WORKDIR /gotham-utilities/server/cognito
RUN ["npm", "install"]

ENV rocket_address=0.0.0.0
ENV rocket_port=8000

EXPOSE 8000
WORKDIR /gotham-server
RUN ["cargo", "build", "--release"]


WORKDIR /integration-tests
RUN ["cargo", "test", "--release", "--", "--nocapture"]

# Server
ENV db=AWS
WORKDIR /gotham-server
CMD ["cargo", "run", "--release"]


