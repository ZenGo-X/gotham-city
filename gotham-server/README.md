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

### Running tests
#### Without timing output
```bash
cargo test --release
```

#### With timing output
```bash
cargo test --release -- --nocapture
```

Example:
```test
gotham-server git:(master) ✗ cargo test --release -- --nocapture
    Finished release [optimized] target(s) in 0.38s
     Running target/release/deps/server_lib-c8356eb8232d5b73

running 1 test
🔧 Configured for production.
    => address: 0.0.0.0
    => port: 8000
    => log: critical
    => workers: 16
    => secret key: generated
    => limits: forms = 32KiB
    => keep-alive: 5s
    => tls: disabled
    
Warning: environment is 'production', but no `secret_key` is configured
PT0.022559567S Network/Server: party1 first message
PT0.018383316S Client: party2 first message
PT0.376486125S Network/Server: party1 second message
PT0.195108919S Client: party2 second message
PT0.007708591S Network/Server: party1 third message
PT0.000000497S Client: party2 third message
PT0.000052484S Network/Server: party1 fourth message
PT0.000002242S Client: party2 fourth message
(took PT0.630324S) test tests::key_gen ... ok
```

## APIs

* `#[post("/keygen/first", format = "json")]`
* `#[post("/keygen/<id>/second", format = "json", data = "<d_log_proof>")]`
* `#[post("/keygen/<id>/third", format = "json", data = "<pdl_chal_c_tag>")]
`
* `#[post("/keygen/<id>/fourth", format = "json", data = "<request>")]
`
