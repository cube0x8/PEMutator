use super::pe::{
    CodeArch, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64, OPTIONAL_MAGIC_PE32,
    OPTIONAL_MAGIC_PE32_PLUS,
};

pub fn machine_family(machine: u16) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_I386 => "x86/pe32",
        IMAGE_FILE_MACHINE_ARMNT => "armnt/pe32",
        IMAGE_FILE_MACHINE_IA64 => "ia64/pe32+",
        IMAGE_FILE_MACHINE_AMD64 => "amd64/pe32+",
        IMAGE_FILE_MACHINE_ARM64 => "arm64/pe32+",
        _ => "other/pe32",
    }
}

pub fn infer_code_arch(machine: u16, optional_magic: u16) -> Option<CodeArch> {
    let arch = match machine {
        IMAGE_FILE_MACHINE_I386 => CodeArch::X86,
        IMAGE_FILE_MACHINE_AMD64 => CodeArch::X64,
        IMAGE_FILE_MACHINE_ARMNT => CodeArch::Arm32,
        IMAGE_FILE_MACHINE_ARM64 => CodeArch::Arm64,
        _ => return None,
    };

    let expected_magic = expected_optional_magic(machine);
    if optional_magic != 0 && optional_magic != expected_magic {
        return None;
    }

    Some(arch)
}

pub fn is_pe32_plus_machine(machine: u16) -> bool {
    matches!(
        machine,
        IMAGE_FILE_MACHINE_IA64 | IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64
    )
}

pub fn canonical_optional_header_size(machine: u16) -> usize {
    if is_pe32_plus_machine(machine) {
        0xf0
    } else {
        0xe0
    }
}

pub fn expected_optional_magic(machine: u16) -> u16 {
    if is_pe32_plus_machine(machine) {
        OPTIONAL_MAGIC_PE32_PLUS
    } else {
        OPTIONAL_MAGIC_PE32
    }
}
