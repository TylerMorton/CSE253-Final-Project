#!/bin/bash

cargo xtask build-ebpf
cargo build
cargo xtask build
RUST_LOG=debug cargo xtask run -- --eth-iface lo --wifi-iface lo --plc-iface lo

