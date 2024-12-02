#!/bin/bash

cargo xtask build-ebpf
cargo build
cargo xtask build

