mod build_ebpf;
mod collect_syscall_data;
mod run;
mod syscall_extractor;

use std::process::exit;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    Run(run::Options),
    CollectSyscallData(collect_syscall_data::Options),
    SyscallExtractor(syscall_extractor::Options),
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        CollectSyscallData(opts) => collect_syscall_data::run(opts),
        Run(opts) => run::run(opts),
        SyscallExtractor(opts) => syscall_extractor::run(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
