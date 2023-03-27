use std::collections::HashMap;

pub struct State {
	syscall_to_id: HashMap<String, u16>,
	id_to_syscall: HashMap<u16, String>,
    syscalls: Vec<String>,
    entry_tracepoints: Vec<String>,
    exit_tracepoints: Vec<String>,
}

impl State {
    pub fn new() -> Self {
        State {
            syscall_to_id: HashMap::new(),
            id_to_syscall: HashMap::new(),
            syscalls: Vec::new(),
            entry_tracepoints: Vec::new(),
            exit_tracepoints: Vec::new(),
        }
    }

    pub fn add_syscall(&mut self, syscall_name: String, syscall_id: u16) {
        self.syscall_to_id.insert(syscall_name.clone(), syscall_id);
        self.id_to_syscall.insert(syscall_id, syscall_name.clone());
        self.syscalls.push(syscall_name);
    }

    pub fn get_syscall_id(&self, syscall_name: String) -> Option<u16> {
        self.syscall_to_id.get(&syscall_name).copied()
    }

    pub fn get_syscall_name(&self, syscall_id: u16) -> Option<String> {
        self.id_to_syscall.get(&syscall_id).cloned()
    }

    pub fn get_syscall_count(&self) -> usize {
        self.syscalls.len()
    }

    pub fn add_tracepoint(&mut self, tracepoint: String) {
        if tracepoint.contains("enter") {
            self.entry_tracepoints.push(tracepoint.clone());
        } else if tracepoint.contains("exit") {
            self.exit_tracepoints.push(tracepoint.clone());
        }
    }

    pub fn get_entry_tracepoint_ref(&self) -> &Vec<String> {
        &self.entry_tracepoints
    }
    
    pub fn get_exit_tracepoint_ref(&self) -> &Vec<String> {
        &self.exit_tracepoints
    }

    pub fn get_tracepoint_count(&self) -> usize {
        self.entry_tracepoints.len()
    }

    pub fn is_syscall(&self, syscall: String) -> bool {
        self.syscalls.contains(&syscall)
    }

    pub fn syscall_has_tracepoint(&self, syscall: String) -> bool {
        self.entry_tracepoints.contains(&String::from("sys_enter_".to_owned() + &syscall))
    }
}
