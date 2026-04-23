use crate::ir::{X64BranchInsn, X64MemOp};

#[derive(Debug, Clone, Copy)]
pub enum SafeReg64 {
    // TODO: xmm, ymm, zmm
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

#[derive(Debug, Clone, Copy)]
pub enum SensitiveReg64 {
    Rsp,
    Rbp,
}

#[derive(Debug, Clone, Copy)]
pub enum Reg64 {
    Safe(SafeReg64),
    Sensitive(SensitiveReg64),
}

#[derive(Debug, Clone, Copy)]
pub enum X86_64Insn {
    // TODO: cmpxchg16b requires rdx:rax, so maybe we should have a separate enum for that?
    // TODO: cmp, test, and other instructions that implicitly use rax should also be considered
    // TODO: jnz, jz, and other instructions that implicitly use rax for zero comparison should also be considered
    PushReg64(Reg64),
    PopReg64(Reg64),
    MovReg64Imm64(Reg64, u64),
    MovReg64Reg64(Reg64, Reg64),
    MovReg64Mem64(Reg64, X64MemOp),
    MovMem64Reg64(X64MemOp, Reg64),
    AddReg64Reg64(Reg64, Reg64),
    SubReg64Reg64(Reg64, Reg64),
    Branch(X64BranchInsn),
    Ret,
}

#[derive(Debug, Clone, Copy)]
pub enum X64InsnKind {
    PushReg64,
    PopReg64,
    MovReg64Imm64,
    MovReg64Reg64,
    MovReg64Mem64,
    MovMem64Reg64,
    AddReg64Reg64,
    SubReg64Reg64,
    JmpRel8,
    JmpRel32,
    CallRel32,
    Ret,
}
