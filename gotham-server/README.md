# Gotham Server
![Gotham Server](../misc/server-icon.png)

## Introduction
Gotham server is a RESTful web service exposing APIs for two party ECDSA key generation and signing.

## Installation
### Launching the server
```bash
git clone https://github.com/KZen-networks/gotham-city.git
cd gotham-city/gotham-server
cargo run --release
```

* By default, the server will use a local [RocksDB](https://rocksdb.org/).<br> 


### Running tests
#### Without timing output
```bash
RUST_TEST_THREADS=1 cargo test --release
```

#### With timing output
```bash
RUST_TEST_THREADS=1  cargo test --release -- --nocapture
```
