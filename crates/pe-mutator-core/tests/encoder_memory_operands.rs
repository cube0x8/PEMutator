use pe_mutator_core::arch::{Reg32, Reg64, SafeReg64, SensitiveReg64, X86_64Insn, X86Insn};
use pe_mutator_core::encoder::{x64::X64Encoder, x86::X86Encoder};
use pe_mutator_core::ir::{X64MemOp, X86MemOp};

#[test]
fn x64_encodes_rip_relative_zero_disp() {
    let insn =
        X86_64Insn::MovReg64Mem64(Reg64::Safe(SafeReg64::Rax), X64MemOp::RipDisp { disp: 0 });
    assert!(X64Encoder::encoded_size(&insn, 0x1000).is_ok());
}

#[test]
fn x64_encodes_rbp_base_without_explicit_disp() {
    let insn = X86_64Insn::MovReg64Mem64(
        Reg64::Safe(SafeReg64::Rax),
        X64MemOp::Base {
            base: Reg64::Sensitive(SensitiveReg64::Rbp),
        },
    );
    assert!(X64Encoder::encoded_size(&insn, 0x1000).is_ok());
}

#[test]
fn x64_encodes_r13_base_without_explicit_disp() {
    let insn = X86_64Insn::MovReg64Mem64(
        Reg64::Safe(SafeReg64::Rax),
        X64MemOp::Base {
            base: Reg64::Safe(SafeReg64::R13),
        },
    );
    assert!(X64Encoder::encoded_size(&insn, 0x1000).is_ok());
}

#[test]
fn x64_encodes_base_disp_outside_i8_range() {
    let insn = X86_64Insn::MovReg64Mem64(
        Reg64::Safe(SafeReg64::Rax),
        X64MemOp::BaseDisp {
            base: Reg64::Safe(SafeReg64::Rbx),
            disp: 128,
        },
    );
    assert!(X64Encoder::encoded_size(&insn, 0x1000).is_ok());
}

#[test]
fn x64_encodes_base_index_scale_disp_outside_i8_range() {
    let insn = X86_64Insn::MovReg64Mem64(
        Reg64::Safe(SafeReg64::Rax),
        X64MemOp::BaseIndexScaleDisp {
            base: Reg64::Safe(SafeReg64::Rbx),
            index: Reg64::Safe(SafeReg64::Rcx),
            scale: 4,
            disp: -129,
        },
    );
    assert!(X64Encoder::encoded_size(&insn, 0x1000).is_ok());
}

#[test]
fn x64_encodes_absolute_signed_32_bit_displacement() {
    let insn = X86_64Insn::MovMem64Reg64(
        X64MemOp::AbsoluteDisp32 { addr: -1_i32 },
        Reg64::Safe(SafeReg64::Rsi),
    );
    assert!(X64Encoder::encoded_size(&insn, 0x1000).is_ok());
}

#[test]
fn x86_encodes_ebp_base_without_explicit_disp() {
    let insn = X86Insn::MovReg32Mem32(Reg32::Eax, X86MemOp::Base { base: Reg32::Ebp });
    assert!(X86Encoder::encoded_size(&insn, 0x1000).is_ok());
}

#[test]
fn x86_reports_instruction_context_for_invalid_index_register() {
    let insn = X86Insn::MovReg32Mem32(
        Reg32::Eax,
        X86MemOp::BaseIndexScale {
            base: Reg32::Ebx,
            index: Reg32::Esp,
            scale: 4,
        },
    );
    let err = X86Encoder::encoded_size(&insn, 0x401000).unwrap_err();
    let err_text = format!("{err}");

    assert!(err_text.contains("iced-x86 encoding failed for x86 insn="));
    assert!(err_text.contains("MovReg32Mem32"));
    assert!(err_text.contains("index: Esp"));
    assert!(err_text.contains("ip=0x401000"));
    assert!(err_text.contains("ESP/RSP can't be used as an index register"));
}
