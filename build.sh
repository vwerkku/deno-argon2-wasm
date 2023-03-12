#!/usr/bin/env bash

cargo build --lib --release --target wasm32-unknown-unknown
wasm-opt -O3 -o ./wasm/argon2.wasm ./target/wasm32-unknown-unknown/release/argon2.wasm
cargo clean
