use crate::arch::Reg64;

use super::BranchTarget;

#[derive(Debug, Clone, Copy)]
pub enum X64BranchWidth {
    Rel8,
    Rel32,
}

#[derive(Debug, Clone, Copy)]
pub enum X64BranchKind {
    Jmp,
    Call,
}

#[derive(Debug, Clone, Copy)]
pub struct X64BranchInsn {
    pub kind: X64BranchKind,
    pub width: X64BranchWidth,
    pub target: BranchTarget,
    pub displacement: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub enum X64MemOp {
    Base {
        base: Reg64,
    },
    BaseDisp {
        base: Reg64,
        disp: i32,
    },
    BaseIndexScale {
        base: Reg64,
        index: Reg64,
        scale: u32,
    },
    BaseIndexScaleDisp {
        base: Reg64,
        index: Reg64,
        scale: u32,
        disp: i32,
    },
    RipDisp {
        disp: i32,
    },
    AbsoluteDisp32 {
        addr: i32,
    },
}
