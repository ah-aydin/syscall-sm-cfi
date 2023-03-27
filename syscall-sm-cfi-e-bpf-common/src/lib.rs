#![no_std]

pub fn str_to_1(s: &str) -> [u8; 1] {
    let mut result = [0; 1];
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len > 1 {
        panic!("String is too long");
    }
    result[..len].copy_from_slice(bytes);
    result
}

pub fn str_to_16(s: &str) -> [u8; 16] {
    let mut result = [0; 16];
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len > 16 {
        panic!("String is too long");
    }
    result[..len].copy_from_slice(bytes);
    result
}

pub fn build_transition(bin_name: &str, from: u16, to: u16) -> [u8; 20] {
    let mut result = [0; 20];

    let bin_bytes = str_to_16(bin_name);
    let from_bytes = from.to_be_bytes();
    let to_bytes = to.to_be_bytes();

    //let bin_len = bin_bytes.len();
    let bin_len = 16;
    let from_len = from_bytes.len();
    let to_len = to_bytes.len();
    if bin_len + from_len + to_len > 20 {
        panic!("String is too long");
    }
    result[..bin_len].copy_from_slice(&bin_bytes);
    result[bin_len..(bin_len + from_len)].copy_from_slice(&from_bytes);
    result[(bin_len + from_len)..(bin_len + from_len + to_len)].copy_from_slice(&to_bytes);

    result
}
