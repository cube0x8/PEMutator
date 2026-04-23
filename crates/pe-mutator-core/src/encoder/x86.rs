use crate::arch::{Reg32, X86Insn};
use crate::encoder::common::memory_displ_size_32;
use crate::encoder::error::{iced_error, iced_error_with_context};
use crate::error::Error;
use crate::ir::{AbstractBlock, X86BranchInsn, X86BranchKind, X86BranchWidth, X86MemOp};
use iced_x86::{Code, Encoder, Instruction, MemoryOperand, Register};

pub struct X86Encoder;

fn lower_reg32(reg: Reg32) -> Register {
    match reg {
        Reg32::Eax => Register::EAX,
        Reg32::Ecx => Register::ECX,
        Reg32::Edx => Register::EDX,
        Reg32::Ebx => Register::EBX,
        Reg32::Esp => Register::ESP,
        Reg32::Ebp => Register::EBP,
        Reg32::Esi => Register::ESI,
        Reg32::Edi => Register::EDI,
    }
}

fn lower_branch_disp(branch: &X86BranchInsn) -> i32 {
    match branch.displacement {
        Some(disp) => disp,
        None => 0,
    }
}

fn lower_x86_mem_op(mem_op: X86MemOp) -> MemoryOperand {
    match mem_op {
        X86MemOp::Base { base } => {
            let base = lower_reg32(base);
            let displ_size = memory_displ_size_32(base, 0);
            MemoryOperand::with_base_displ_size(base, 0, displ_size)
        }
        X86MemOp::BaseDisp { base, disp } => {
            let base = lower_reg32(base);
            let displ_size = memory_displ_size_32(base, disp);
            MemoryOperand::with_base_displ_size(base, disp as i64, displ_size)
        }
        X86MemOp::BaseIndexScale { base, index, scale } => {
            let base = lower_reg32(base);
            let displ_size = memory_displ_size_32(base, 0);
            MemoryOperand::new(
                base,
                lower_reg32(index),
                scale,
                0,
                displ_size,
                false,
                Register::None,
            )
        }
        X86MemOp::BaseIndexScaleDisp {
            base,
            index,
            scale,
            disp,
        } => {
            let base = lower_reg32(base);
            let displ_size = memory_displ_size_32(base, disp);
            MemoryOperand::new(
                base,
                lower_reg32(index),
                scale,
                disp as i64,
                displ_size,
                false,
                Register::None,
            )
        }
        X86MemOp::Absolute { addr } => {
            MemoryOperand::with_base_displ_size(Register::None, addr as i64, 4)
        }
    }
}

fn lower_insn(insn: &X86Insn, ip: u64) -> Result<Instruction, Error> {
    match insn {
        X86Insn::PushReg32(reg) => {
            Instruction::with1(Code::Push_r32, lower_reg32(*reg)).map_err(iced_error)
        }
        X86Insn::PopReg32(reg) => {
            Instruction::with1(Code::Pop_rm32, lower_reg32(*reg)).map_err(iced_error)
        }
        X86Insn::MovReg32Imm32(reg, imm) => {
            Instruction::with2(Code::Mov_r32_imm32, lower_reg32(*reg), *imm).map_err(iced_error)
        }
        X86Insn::MovReg32Reg32(dst, src) => {
            Instruction::with2(Code::Mov_r32_rm32, lower_reg32(*dst), lower_reg32(*src))
                .map_err(iced_error)
        }
        X86Insn::MovReg32Mem32(reg, mem_op) => {
            let mem = lower_x86_mem_op(*mem_op);
            Instruction::with2(Code::Mov_r32_rm32, lower_reg32(*reg), mem).map_err(iced_error)
        }
        X86Insn::MovMem32Reg32(mem_op, reg) => {
            let mem = lower_x86_mem_op(*mem_op);
            Instruction::with2(Code::Mov_rm32_r32, mem, lower_reg32(*reg)).map_err(iced_error)
        }
        X86Insn::AddReg32Reg32(dst, src) => {
            Instruction::with2(Code::Add_r32_rm32, lower_reg32(*dst), lower_reg32(*src))
                .map_err(iced_error)
        }
        X86Insn::SubReg32Reg32(dst, src) => {
            Instruction::with2(Code::Sub_r32_rm32, lower_reg32(*dst), lower_reg32(*src))
                .map_err(iced_error)
        }
        X86Insn::Branch(branch) => {
            let (code, instr_len) = match (branch.kind, branch.width) {
                (X86BranchKind::Jmp, X86BranchWidth::Rel8) => (Code::Jmp_rel8_32, 2_u64),
                (X86BranchKind::Jmp, X86BranchWidth::Rel32) => (Code::Jmp_rel32_32, 5_u64),
                (X86BranchKind::Call, X86BranchWidth::Rel32) => (Code::Call_rel32_32, 5_u64),
                (X86BranchKind::Call, X86BranchWidth::Rel8) => {
                    return Err(Error::illegal_argument(
                        "x86 call rel8 is not a supported encoding",
                    ));
                }
            };
            let target = ip
                .wrapping_add(instr_len)
                .wrapping_add(lower_branch_disp(branch) as i64 as u64);
            Instruction::with_branch(code, target).map_err(iced_error)
        }
        X86Insn::Ret => Ok(Instruction::with(Code::Retnd)),
    }
}

impl X86Encoder {
    pub fn encoded_size(insn: &X86Insn, ip: u64) -> Result<usize, Error> {
        let lowered_insn = lower_insn(insn, ip)
            .map_err(|err| iced_error_with_context("x86", "lowering", insn, ip, err))?;
        let mut encoder = Encoder::new(32);
        Ok(encoder
            .encode(&lowered_insn, ip)
            .map_err(|err| iced_error_with_context("x86", "encoding", insn, ip, err))?)
    }

    fn encode_insn(insn: &X86Insn, ip: u64) -> Result<Vec<u8>, Error> {
        if let X86Insn::Branch(branch) = insn {
            if branch.displacement.is_none() {
                return Err(Error::illegal_argument(
                    "cannot encode an unresolved x86 branch instruction",
                ));
            }
        }

        let lowered_insn = lower_insn(insn, ip)
            .map_err(|err| iced_error_with_context("x86", "lowering", insn, ip, err))?;
        let mut encoder = Encoder::new(32);
        encoder
            .encode(&lowered_insn, ip)
            .map_err(|err| iced_error_with_context("x86", "encoding", insn, ip, err))?;
        Ok(encoder.take_buffer())
    }

    pub fn encode_block(block: &AbstractBlock<X86Insn>, base_ip: u64) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        let mut current_ip = base_ip;
        for insn in &block.insns {
            let insn_bytes = Self::encode_insn(insn, current_ip)?;
            bytes.extend_from_slice(&insn_bytes);
            current_ip += insn_bytes.len() as u64;
        }
        Ok(bytes)
    }
}
