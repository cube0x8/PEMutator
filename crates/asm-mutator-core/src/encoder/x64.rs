use crate::arch::{Reg64, SafeReg64, SensitiveReg64, X86_64Insn};
use crate::encoder::common::memory_displ_size_64;
use crate::encoder::error::{iced_error, iced_error_with_context};
use crate::error::Error;
use crate::ir::{AbstractBlock, X64BranchInsn, X64BranchKind, X64BranchWidth, X64MemOp};
use iced_x86::{Code, Encoder, Instruction, MemoryOperand, Register};

pub struct X64Encoder;

fn lower_reg64(reg: Reg64) -> Register {
    match reg {
        Reg64::Safe(safe) => match safe {
            SafeReg64::Rax => Register::RAX,
            SafeReg64::Rcx => Register::RCX,
            SafeReg64::Rdx => Register::RDX,
            SafeReg64::Rbx => Register::RBX,
            SafeReg64::Rsi => Register::RSI,
            SafeReg64::Rdi => Register::RDI,
            SafeReg64::R8 => Register::R8,
            SafeReg64::R9 => Register::R9,
            SafeReg64::R10 => Register::R10,
            SafeReg64::R11 => Register::R11,
            SafeReg64::R12 => Register::R12,
            SafeReg64::R13 => Register::R13,
            SafeReg64::R14 => Register::R14,
            SafeReg64::R15 => Register::R15,
        },
        Reg64::Sensitive(sensitive) => match sensitive {
            SensitiveReg64::Rsp => Register::RSP,
            SensitiveReg64::Rbp => Register::RBP,
        },
    }
}

fn lower_branch_disp(branch: &X64BranchInsn) -> i32 {
    match branch.displacement {
        Some(disp) => disp,
        None => 0,
    }
}

fn lower_x64_mem_op(mem_op: X64MemOp) -> MemoryOperand {
    match mem_op {
        X64MemOp::Base { base } => {
            let base = lower_reg64(base);
            let displ_size = memory_displ_size_64(base, 0);
            MemoryOperand::with_base_displ_size(base, 0, displ_size)
        }
        X64MemOp::BaseDisp { base, disp } => {
            let base = lower_reg64(base);
            let displ_size = memory_displ_size_64(base, disp);
            MemoryOperand::with_base_displ_size(base, disp as i64, displ_size)
        }
        X64MemOp::BaseIndexScale { base, index, scale } => {
            let base = lower_reg64(base);
            let displ_size = memory_displ_size_64(base, 0);
            MemoryOperand::new(
                base,
                lower_reg64(index),
                scale,
                0,
                displ_size,
                false,
                Register::None,
            )
        }
        X64MemOp::BaseIndexScaleDisp {
            base,
            index,
            scale,
            disp,
        } => {
            let base = lower_reg64(base);
            let displ_size = memory_displ_size_64(base, disp);
            MemoryOperand::new(
                base,
                lower_reg64(index),
                scale,
                disp as i64,
                displ_size,
                false,
                Register::None,
            )
        }
        X64MemOp::RipDisp { disp } => MemoryOperand::new(
            Register::RIP,
            Register::None,
            1,
            disp as i64,
            memory_displ_size_64(Register::RIP, disp),
            false,
            Register::None,
        ),
        X64MemOp::AbsoluteDisp32 { addr } => {
            // This path models offset-only addressing as a signed 32-bit displacement,
            // matching the subset encodable by the general x64 memory operand form.
            MemoryOperand::with_base_displ_size(Register::None, addr as i64, 4)
        }
    }
}

fn lower_insn(insn: &X86_64Insn, ip: u64) -> Result<Instruction, Error> {
    match insn {
        X86_64Insn::PushReg64(reg) => {
            Instruction::with1(Code::Push_r64, lower_reg64(*reg)).map_err(iced_error)
        }
        X86_64Insn::PopReg64(reg) => {
            Instruction::with1(Code::Pop_rm64, lower_reg64(*reg)).map_err(iced_error)
        }
        X86_64Insn::MovReg64Imm64(reg, imm) => {
            Instruction::with2(Code::Mov_r64_imm64, lower_reg64(*reg), *imm).map_err(iced_error)
        }
        X86_64Insn::MovReg64Reg64(dst, src) => {
            Instruction::with2(Code::Mov_r64_rm64, lower_reg64(*dst), lower_reg64(*src))
                .map_err(iced_error)
        }
        X86_64Insn::MovReg64Mem64(reg, mem_op) => {
            let mem = lower_x64_mem_op(*mem_op);
            Instruction::with2(Code::Mov_r64_rm64, lower_reg64(*reg), mem).map_err(iced_error)
        }
        X86_64Insn::MovMem64Reg64(mem_op, reg) => {
            let mem = lower_x64_mem_op(*mem_op);
            Instruction::with2(Code::Mov_rm64_r64, mem, lower_reg64(*reg)).map_err(iced_error)
        }
        X86_64Insn::AddReg64Reg64(dst, src) => {
            Instruction::with2(Code::Add_r64_rm64, lower_reg64(*dst), lower_reg64(*src))
                .map_err(iced_error)
        }
        X86_64Insn::SubReg64Reg64(dst, src) => {
            Instruction::with2(Code::Sub_r64_rm64, lower_reg64(*dst), lower_reg64(*src))
                .map_err(iced_error)
        }
        X86_64Insn::Branch(branch) => {
            let (code, instr_len) = match (branch.kind, branch.width) {
                (X64BranchKind::Jmp, X64BranchWidth::Rel8) => (Code::Jmp_rel8_64, 2_u64),
                (X64BranchKind::Jmp, X64BranchWidth::Rel32) => (Code::Jmp_rel32_64, 5_u64),
                (X64BranchKind::Call, X64BranchWidth::Rel32) => (Code::Call_rel32_64, 5_u64),
                (X64BranchKind::Call, X64BranchWidth::Rel8) => {
                    return Err(Error::illegal_argument(
                        "x64 call rel8 is not a supported encoding",
                    ));
                }
            };
            let target = ip
                .wrapping_add(instr_len)
                .wrapping_add(lower_branch_disp(branch) as i64 as u64);
            Instruction::with_branch(code, target).map_err(iced_error)
        }
        X86_64Insn::Ret => Ok(Instruction::with(Code::Retnq)),
    }
}

impl X64Encoder {
    pub fn encoded_size(insn: &X86_64Insn, ip: u64) -> Result<usize, Error> {
        let lowered_insn = lower_insn(insn, ip)
            .map_err(|err| iced_error_with_context("x64", "lowering", insn, ip, err))?;
        let mut encoder = Encoder::new(64);
        Ok(encoder
            .encode(&lowered_insn, ip)
            .map_err(|err| iced_error_with_context("x64", "encoding", insn, ip, err))?)
    }

    fn encode_insn(insn: &X86_64Insn, ip: u64) -> Result<Vec<u8>, Error> {
        if let X86_64Insn::Branch(branch) = insn {
            if branch.displacement.is_none() {
                return Err(Error::illegal_argument(
                    "cannot encode an unresolved x64 branch instruction",
                ));
            }
        }

        let lowered_insn = lower_insn(insn, ip)
            .map_err(|err| iced_error_with_context("x64", "lowering", insn, ip, err))?;
        let mut encoder = Encoder::new(64);
        encoder
            .encode(&lowered_insn, ip)
            .map_err(|err| iced_error_with_context("x64", "encoding", insn, ip, err))?;
        Ok(encoder.take_buffer())
    }

    pub fn encode_block(block: &AbstractBlock<X86_64Insn>, base_ip: u64) -> Result<Vec<u8>, Error> {
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
