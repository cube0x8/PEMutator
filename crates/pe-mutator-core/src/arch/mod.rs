pub mod x64;
pub mod x86;

pub use x64::*;
pub use x86::*;

pub enum Arm32Insn {
    PushReg(u8),
    PopReg(u8),
    MovRegImm(u8, u32),
    MovRegReg(u8, u8),
    MovRegMem(u8, u32),
    MovMemReg(u32, u8),
    AddRegReg(u8, u8),
    SubRegReg(u8, u8),
    BRel(i32),
    BlRel(i32),
    Ret,
}

pub enum Arm64Insn {
    PushReg(u8),
    PopReg(u8),
    MovRegImm(u8, u64),
    MovRegReg(u8, u8),
    MovRegMem(u8, u32),
    MovMemReg(u32, u8),
    AddRegReg(u8, u8),
    SubRegReg(u8, u8),
    BRel(i32),
    BlRel(i32),
    Ret,
}
