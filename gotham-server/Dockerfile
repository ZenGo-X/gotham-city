FROM amazonlinux:latest

RUN yum install -y make automake gcc gcc-c++ kernel-devel
RUN yum install -y gmp-devel
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly
RUN $HOME/.cargo/bin/cargo --version
COPY . .
RUN $HOME/.cargo/bin/cargo run --release