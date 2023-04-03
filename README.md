# Runtime Security with Syscall State-Machine (eBPF) - BSc. Thesis Project

This is a proof of concept eBPF program for runtime security. It tracks, the syscall state machine with a max depth of 2. Extraction of the syscall state machine of a binary file is done by running `strace` and putting the
output of the file inside the `res` folder with `.syscall` extention and running the subproject `syscall-extractor`.

The userspace program attaches eBPF programs to all the syscall tracepoints that are available on the machine and tracks the given binaries.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
2. Install a rust nightly toolchain with the rust-src component: `rustup toolchain install nightly --component rust-src`
3. Install bpf-linker: `cargo install bpf-linker`

## Project structure

1. syscall_extractor 
    - extracts the syscall state machine from `.syscall` files found in `res` folder as `.json`. The `.syscall` files are generated using `strace -o my_file.syscall my-binary`.
2. syscalls
    - collection of common code that is used in `syscall-sm-cfi-e-bpf` and `syscall_extractor`.
    - fetches syscall state from the machine.
    - IMPORTANT, there is a variable that need attention. `UNISTD_SRC_DIR` should point towards the header file in your system that contains the syscall function names and their id's. Pick the one that fits your architecture.
3. syscall-sm-cfi-e-bpf
    - userspace program that populates the tables from the `.json` files inside the `res` folder and attaches the kernel space program to all syscall tracepoints.
4. syscall-sm-cfi-e-bpf-common
    - contains common code used by `syscall-sm-cfi-e-bpf` and `syscall-sm-cfi-e-bpf-ebpf`.
    - this is a `no std` crate
5. syscall-sm-cfi-e-bpf-ebpf
    - kernel space eBPF program.

## Build 

```bash
# Build kernel space program
cargo xtask build-ebpf

# Generate .json files in .res/ from .syscall files
cargo xtask syscall-extractor

# Run userspace
RUST_LOG=info cargo xtask run
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Limitations

- Curentlly the binary names should be at most 16 characters. It is a limitation imposed by `bpf_get_current_comm()` helper function, which returns a `[u8; 16]`.
- The generation of syscall state machine is not ideal, but that is it's own thesis topic.
