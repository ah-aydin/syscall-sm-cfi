use std::{
    fs::{File, self},
    io::Read,
    str::from_utf8,
    collections::HashMap,
    path::PathBuf,
};
use log::{info, error};

fn process_file(file_path: PathBuf) {
    let binary_name = file_path.file_stem().unwrap().to_str().unwrap().clone();
    info!("Processing for binary: {}", binary_name);

    let mut syscall_sm: HashMap<String, Vec<String>> = HashMap::new();
    let mut syscall_file = File::open(file_path.clone()).unwrap();
    let mut syscall_buffer = Vec::new();
    syscall_file.read_to_end(&mut syscall_buffer).unwrap();
    
    let syscall_file_lines = from_utf8(&syscall_buffer).unwrap().split("\n");
    let mut prev_syscall: Option<String> = Option::None;
    for line in syscall_file_lines {
        match line.find("(") {
            Some(length) => {
                let syscall = line[0..length].to_string();
                if !syscalls::is_syscall(syscall.clone()) || !syscalls::syscall_has_tracepoint(syscall.clone()) {
                    error!("Found syscall that does not exist, or one that does not have a tracepoint");
                    continue;
                }

                if !syscall_sm.contains_key(&syscall) {
                    syscall_sm.insert(syscall.clone(), Vec::new());
                }

                if prev_syscall.is_some() {
                    let prev_syscall_val = prev_syscall.unwrap();
                    info!("Link: {} -> {}", prev_syscall_val.clone(), syscall);
                    if !syscall_sm.get(&prev_syscall_val).unwrap().contains(&syscall) {
                        syscall_sm.get_mut(&prev_syscall_val).unwrap().push(syscall.clone());
                    }
                }
                prev_syscall = Some(syscall);
            }
            None => {}
        };
    }

    let json_data = syscalls::state_machine_data::StateMachineData { 
        binary: String::from(binary_name),
        data: syscall_sm.clone(),
    };

    let json_string = serde_json::to_string(&json_data).unwrap();
    std::fs::write(format!("res/{}.json", binary_name), json_string).unwrap();
}

fn main() {
    env_logger::init();
    syscalls::init();

    let entries = fs::read_dir(syscalls::RES_DIR).unwrap();
    
    for entry in entries {
        match entry {
            Ok(entry) => {
                if entry.path().extension().unwrap() != "syscall" {
                    continue;
                }
                info!("{}", syscalls::DEBUG_STR);
                info!("Found syscall file {}", entry.file_name().into_string().unwrap());
                process_file(entry.path());
                info!("{}", syscalls::DEBUG_STR);
            }
            Err(_) => {}
        };
    }
}
