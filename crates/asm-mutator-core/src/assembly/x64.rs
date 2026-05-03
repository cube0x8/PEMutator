use crate::arch::{Reg64, SafeReg64, SensitiveReg64, X64InsnKind, X86_64Insn};
use crate::assembly::common::{
    ensure_branch_target_in_section, random_branch_target, random_short_branch_target,
    resolve_branch_target_va,
};
use crate::encoder::x64::X64Encoder;
use crate::error::Error;
use crate::ir::{
    AbstractBlock, PlacementContext, X64BranchInsn, X64BranchKind, X64BranchWidth, X64MemOp,
};
use crate::rng::MutRng;

pub struct X64AssemblyGenerator;

const X64_KINDS: &[X64InsnKind] = &[
    X64InsnKind::PushReg64,
    X64InsnKind::PopReg64,
    X64InsnKind::MovReg64Imm64,
    X64InsnKind::MovReg64Reg64,
    X64InsnKind::MovReg64Mem64,
    X64InsnKind::MovMem64Reg64,
    X64InsnKind::AddReg64Reg64,
    X64InsnKind::SubReg64Reg64,
    X64InsnKind::JmpRel8,
    X64InsnKind::JmpRel32,
    X64InsnKind::CallRel32,
    X64InsnKind::Ret,
];

const X64_REGS_SAFE: &[Reg64] = &[
    Reg64::Safe(SafeReg64::Rax),
    Reg64::Safe(SafeReg64::Rcx),
    Reg64::Safe(SafeReg64::Rdx),
    Reg64::Safe(SafeReg64::Rbx),
    Reg64::Safe(SafeReg64::Rsi),
    Reg64::Safe(SafeReg64::Rdi),
    Reg64::Safe(SafeReg64::R8),
    Reg64::Safe(SafeReg64::R9),
    Reg64::Safe(SafeReg64::R10),
    Reg64::Safe(SafeReg64::R11),
    Reg64::Safe(SafeReg64::R12),
    Reg64::Safe(SafeReg64::R13),
    Reg64::Safe(SafeReg64::R14),
    Reg64::Safe(SafeReg64::R15),
];

const X64_REGS: &[Reg64] = &[
    Reg64::Safe(SafeReg64::Rax),
    Reg64::Safe(SafeReg64::Rcx),
    Reg64::Safe(SafeReg64::Rdx),
    Reg64::Safe(SafeReg64::Rbx),
    Reg64::Safe(SafeReg64::Rsi),
    Reg64::Safe(SafeReg64::Rdi),
    Reg64::Safe(SafeReg64::R8),
    Reg64::Safe(SafeReg64::R9),
    Reg64::Safe(SafeReg64::R10),
    Reg64::Safe(SafeReg64::R11),
    Reg64::Safe(SafeReg64::R12),
    Reg64::Safe(SafeReg64::R13),
    Reg64::Safe(SafeReg64::R14),
    Reg64::Safe(SafeReg64::R15),
    Reg64::Sensitive(SensitiveReg64::Rsp),
    Reg64::Sensitive(SensitiveReg64::Rbp),
];

impl X64AssemblyGenerator {
    fn random_safe_register<R: MutRng>(rand: &mut R) -> Reg64 {
        X64_REGS_SAFE[rand.below(X64_REGS_SAFE.len())]
    }

    fn random_register<R: MutRng>(rand: &mut R) -> Reg64 {
        X64_REGS[rand.below(X64_REGS.len())]
    }

    fn random_scale<R: MutRng>(rand: &mut R) -> u32 {
        match rand.below(4) {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        }
    }

    fn random_absolute_disp32<R: MutRng>(rand: &mut R) -> i32 {
        // Offset-only memory operands in this encoder path are modeled as signed 32-bit displacements.
        rand.next_u64() as i32
    }

    fn random_mem_op<R: MutRng>(rand: &mut R) -> X64MemOp {
        match rand.below(6) {
            0 => X64MemOp::Base {
                base: Self::random_register(rand),
            },
            1 => X64MemOp::BaseDisp {
                base: Self::random_register(rand),
                disp: rand.next_u64() as i32,
            },
            2 => X64MemOp::BaseIndexScale {
                base: Self::random_register(rand),
                index: Self::random_safe_register(rand),
                scale: Self::random_scale(rand),
            },
            3 => X64MemOp::BaseIndexScaleDisp {
                base: Self::random_register(rand),
                index: Self::random_safe_register(rand),
                scale: Self::random_scale(rand),
                disp: rand.next_u64() as i32,
            },
            4 => X64MemOp::RipDisp {
                disp: rand.next_u64() as i32,
            },
            _ => X64MemOp::AbsoluteDisp32 {
                addr: Self::random_absolute_disp32(rand),
            },
        }
    }

    fn random_insn<R: MutRng>(rand: &mut R) -> X86_64Insn {
        let kind = X64_KINDS[rand.below(X64_KINDS.len())];
        match kind {
            X64InsnKind::PushReg64 => X86_64Insn::PushReg64(Self::random_safe_register(rand)),
            X64InsnKind::PopReg64 => X86_64Insn::PopReg64(Self::random_safe_register(rand)),
            X64InsnKind::MovReg64Imm64 => {
                X86_64Insn::MovReg64Imm64(Self::random_register(rand), rand.next_u64())
            }
            X64InsnKind::MovReg64Reg64 => {
                X86_64Insn::MovReg64Reg64(Self::random_register(rand), Self::random_register(rand))
            }
            X64InsnKind::MovReg64Mem64 => {
                X86_64Insn::MovReg64Mem64(Self::random_register(rand), Self::random_mem_op(rand))
            }
            X64InsnKind::MovMem64Reg64 => {
                X86_64Insn::MovMem64Reg64(Self::random_mem_op(rand), Self::random_register(rand))
            }
            X64InsnKind::AddReg64Reg64 => {
                X86_64Insn::AddReg64Reg64(Self::random_register(rand), Self::random_register(rand))
            }
            X64InsnKind::SubReg64Reg64 => {
                X86_64Insn::SubReg64Reg64(Self::random_register(rand), Self::random_register(rand))
            }
            X64InsnKind::JmpRel8 => X86_64Insn::Branch(X64BranchInsn {
                kind: X64BranchKind::Jmp,
                width: X64BranchWidth::Rel8,
                target: random_short_branch_target(rand),
                displacement: None,
            }),
            X64InsnKind::JmpRel32 => X86_64Insn::Branch(X64BranchInsn {
                kind: X64BranchKind::Jmp,
                width: X64BranchWidth::Rel32,
                target: random_branch_target(rand),
                displacement: None,
            }),
            X64InsnKind::CallRel32 => X86_64Insn::Branch(X64BranchInsn {
                kind: X64BranchKind::Call,
                width: X64BranchWidth::Rel32,
                target: random_branch_target(rand),
                displacement: None,
            }),
            X64InsnKind::Ret => X86_64Insn::Ret,
        }
    }

    pub fn generate_block<R: MutRng>(
        rand: &mut R,
        n_instructions: usize,
    ) -> AbstractBlock<X86_64Insn> {
        let mut block = Vec::new();
        for _ in 0..n_instructions {
            block.push(Self::random_insn(rand));
        }
        AbstractBlock { insns: block }
    }

    pub fn generate_block_max_size<R: MutRng>(
        rand: &mut R,
        base_ip: u64,
        max_size: usize,
    ) -> Result<AbstractBlock<X86_64Insn>, Error> {
        if max_size == 0 {
            return Ok(AbstractBlock { insns: Vec::new() });
        }

        let mut block = Vec::new();
        let mut current_ip = base_ip;
        let mut current_size = 0_usize;

        while current_size < max_size {
            let mut candidate = None;
            for _ in 0..16 {
                let insn = Self::random_insn(rand);
                let insn_size = X64Encoder::encoded_size(&insn, current_ip)?;
                if current_size + insn_size <= max_size {
                    candidate = Some((insn, insn_size));
                    break;
                }
            }

            let Some((insn, insn_size)) = candidate else {
                break;
            };

            current_ip += insn_size as u64;
            current_size += insn_size;
            block.push(insn);
        }

        if block.is_empty() {
            return Err(Error::illegal_argument(format!(
                "failed to generate an x64 block within max_size={max_size}"
            )));
        }

        Ok(AbstractBlock { insns: block })
    }

    pub fn resolve_branches<R: MutRng>(
        rand: &mut R,
        block: &mut AbstractBlock<X86_64Insn>,
        placement_context: &PlacementContext,
    ) -> Result<(), Error> {
        let mut insn_offsets = Vec::with_capacity(block.insns.len());
        let mut offset = 0_u64;
        for insn in &block.insns {
            insn_offsets.push(offset);
            offset +=
                X64Encoder::encoded_size(insn, placement_context.block_base_va + offset)? as u64;
        }

        let block_len = offset;
        let block_end_va = placement_context.block_base_va + block_len;

        for (index, insn) in block.insns.iter_mut().enumerate() {
            let X86_64Insn::Branch(branch) = insn else {
                continue;
            };

            let insn_offset = insn_offsets[index];
            let insn_ip = placement_context.block_base_va + insn_offset;
            let insn_len = X64Encoder::encoded_size(&X86_64Insn::Branch(*branch), insn_ip)? as u64;
            let next_ip = insn_ip + insn_len;
            let (min_displacement, max_displacement) = match branch.width {
                X64BranchWidth::Rel8 => (i8::MIN as i64, i8::MAX as i64),
                X64BranchWidth::Rel32 => (i32::MIN as i64, i32::MAX as i64),
            };

            let target_va = resolve_branch_target_va(
                rand,
                branch.target,
                index,
                &insn_offsets,
                placement_context,
                block_end_va,
                next_ip,
                min_displacement,
                max_displacement,
            )?;
            ensure_branch_target_in_section(target_va, placement_context)?;

            let displacement = (target_va as i128) - (next_ip as i128);
            match branch.width {
                X64BranchWidth::Rel8 => {
                    if !(-128..=127).contains(&displacement) {
                        return Err(Error::illegal_argument(format!(
                            "resolved rel8 branch displacement out of range: {displacement}"
                        )));
                    }
                }
                X64BranchWidth::Rel32 => {
                    if displacement < i32::MIN as i128 || displacement > i32::MAX as i128 {
                        return Err(Error::illegal_argument(format!(
                            "resolved rel32 branch displacement out of range: {displacement}"
                        )));
                    }
                }
            }

            branch.displacement = Some(displacement as i32);
        }

        Ok(())
    }
}
