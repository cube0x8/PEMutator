use iced_x86::Register;

fn memory_displ_size(base: Register, disp: i32, full_size: u32) -> u32 {
    if base == Register::RIP {
        // RIP-relative operands always encode a 32-bit displacement.
        4
    } else if disp == 0 {
        match base {
            Register::EBP | Register::RBP | Register::R13 => 1,
            _ => 0,
        }
    } else if i8::try_from(disp).is_ok() {
        1
    } else {
        full_size
    }
}

pub fn memory_displ_size_32(base: Register, disp: i32) -> u32 {
    memory_displ_size(base, disp, 4)
}

pub fn memory_displ_size_64(base: Register, disp: i32) -> u32 {
    memory_displ_size(base, disp, 8)
}
