use crate::arch::Reg32;

use super::BranchTarget;

#[derive(Debug, Clone, Copy)]
pub enum X86BranchWidth {
    Rel8,
    Rel32,
}

#[derive(Debug, Clone, Copy)]
pub enum X86BranchKind {
    Jmp,
    Call,
}

#[derive(Debug, Clone, Copy)]
pub struct X86BranchInsn {
    pub kind: X86BranchKind,
    pub width: X86BranchWidth,
    pub target: BranchTarget,
    pub displacement: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub enum X86MemOp {
    Base {
        base: Reg32,
    },
    BaseDisp {
        base: Reg32,
        disp: i32,
    },
    BaseIndexScale {
        base: Reg32,
        index: Reg32,
        scale: u32,
    },
    BaseIndexScaleDisp {
        base: Reg32,
        index: Reg32,
        scale: u32,
        disp: i32,
    },
    Absolute {
        addr: u32,
    },
}
