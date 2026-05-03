use crate::ir::{X86BranchInsn, X86MemOp};

#[derive(Debug, Clone, Copy)]
pub enum Reg32 {
    Eax,
    Ecx,
    Edx,
    Ebx,
    Esp,
    Ebp,
    Esi,
    Edi,
}

#[derive(Debug, Clone, Copy)]
pub enum X86Insn {
    PushReg32(Reg32),
    PopReg32(Reg32),
    MovReg32Imm32(Reg32, u32),
    MovReg32Reg32(Reg32, Reg32),
    MovReg32Mem32(Reg32, X86MemOp),
    MovMem32Reg32(X86MemOp, Reg32),
    AddReg32Reg32(Reg32, Reg32),
    SubReg32Reg32(Reg32, Reg32),
    Branch(X86BranchInsn),
    Ret,
}

#[derive(Debug, Clone, Copy)]
pub enum X86InsnKind {
    PushReg32,
    PopReg32,
    MovReg32Imm32,
    MovReg32Reg32,
    MovReg32Mem32,
    MovMem32Reg32,
    AddReg32Reg32,
    SubReg32Reg32,
    JmpRel8,
    JmpRel32,
    CallRel32,
    Ret,
}
