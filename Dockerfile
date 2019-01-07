FROM liuchong/rustup

ENV rocket_address=0.0.0.0
ENV rocket_port=8080

ADD gotham-server /app
WORKDIR /app

RUN rustup default nightly
RUN cargo build --release

EXPOSE 8080
CMD ["cargo", "run", "--release"]