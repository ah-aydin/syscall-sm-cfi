mod state;
pub mod state_machine_data;

use std::{
    fs::{
        File,
        read_dir
    },
    io::Read,
    str::from_utf8,
};
use log::info;
use state::State;

pub const RES_DIR: &str = "/home/hamza/Dev/syscall-sm-cfi-e-bpf/res/";
pub const DEBUG_STR: &str = "============================================================";

static mut GLOBAL_STATE: Option<State> = None;

// Change this to the SRC dir of unistd.h file that coresponds the the machines architecture
const UNISTD_SRC_DIR: &str = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h";
const STD_PREFIX: &str = "#define __NR_";

pub fn init() {

    unsafe { GLOBAL_STATE = Some(State::new()) };

    // Get data from unist file
    let mut unistd_src_file = File::open(UNISTD_SRC_DIR).unwrap();
    let mut unistd_src_buffer = Vec::new();
    unistd_src_file.read_to_end(&mut unistd_src_buffer).unwrap();

    let unistd_src_lines = from_utf8(&unistd_src_buffer).unwrap().split("\n");
    for line in unistd_src_lines {
        if !line.contains(STD_PREFIX) {
            continue;
        }
        let data = &line[STD_PREFIX.len()..];
        let mut data_split = data.split_whitespace();
        let syscall_name = data_split.next().unwrap();
        let syscall_id: u16 = data_split.next().unwrap().parse().unwrap();
        info!("Adding syscall {:3} | {}", syscall_id, syscall_name);

        unsafe { GLOBAL_STATE.as_mut().unwrap().add_syscall(String::from(syscall_name), syscall_id) };
    }
    
    // Get list of kernel tracepoints for the eBPF program
    let tracepoint_dirs = read_dir("/sys/kernel/debug/tracing/events/syscalls").unwrap();
    for dir in tracepoint_dirs {
        let entry = dir.unwrap();
        if entry.file_type().unwrap().is_dir() {
            info!("Found tracepoint: {}", entry.file_name().to_string_lossy());
            unsafe { GLOBAL_STATE.as_mut().unwrap().add_tracepoint(String::from(entry.file_name().to_string_lossy())) };
        }
    }

    info!("Found {} syscalls", unsafe {GLOBAL_STATE.as_ref().unwrap().get_syscall_count() });
    info!("Found {} tracepoints", unsafe {GLOBAL_STATE.as_ref().unwrap().get_tracepoint_count() });
}

pub fn get_syscall_id(syscall_name: String) -> Option<u16> {
    unsafe { GLOBAL_STATE.as_ref().unwrap().get_syscall_id(syscall_name) }
}

pub fn get_syscall_name(syscall_id: u16) -> Option<String> {
    unsafe { GLOBAL_STATE.as_ref().unwrap().get_syscall_name(syscall_id) }
}

pub fn get_entry_tracepoints() -> &'static Vec<String> {
    unsafe { GLOBAL_STATE.as_ref().unwrap().get_entry_tracepoint_ref() }
}

pub fn get_exit_tracepoints() -> &'static Vec<String> {
    unsafe { GLOBAL_STATE.as_ref().unwrap().get_exit_tracepoint_ref() }
}

pub fn is_syscall(syscall: String) -> bool {
    unsafe { GLOBAL_STATE.as_ref().unwrap().is_syscall(syscall) }
}

pub fn syscall_has_tracepoint(syscall: String) -> bool {
    unsafe { GLOBAL_STATE.as_ref().unwrap().syscall_has_tracepoint(syscall) }
}
