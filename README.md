# syscall-sm-cfi-e-bpf

This is a proof of concept eBPF program for runtime security. It tracks, the syscall state machine with a max depth of 2. Extraction of the syscall state machine of a binary file is done by running `strace` and putting the
output of the file inside the `res` folder with `.syscall` extention and running the subproject `syscall-extractor`.

The userspace program attaches eBPF programs to all the syscall tracepoints that are available on the machine and tracks the given binaries.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain with the rust-src component: `rustup toolchain install nightly --component rust-src`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

- Attaches eBPF programs.
- Populates the eBPF maps from the `.json` files located in `res` folder.

```bash
cargo build
```

## Generate syscall state machine

- Generates `.json` files which contain the syscall state machine of the binary, extracte from the `.syscall` files located inside `res` folder.

```bash
cargo xtask syscall-extractor
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
