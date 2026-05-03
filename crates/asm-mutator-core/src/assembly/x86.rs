use crate::arch::{Reg32, X86Insn, X86InsnKind};
use crate::assembly::common::{
    ensure_branch_target_in_section, random_branch_target, random_short_branch_target,
    resolve_branch_target_va,
};
use crate::encoder::x86::X86Encoder;
use crate::error::Error;
use crate::ir::{
    AbstractBlock, PlacementContext, X86BranchInsn, X86BranchKind, X86BranchWidth, X86MemOp,
};
use crate::rng::MutRng;

pub struct X86AssemblyGenerator;

const X86_KINDS: &[X86InsnKind] = &[
    X86InsnKind::PushReg32,
    X86InsnKind::PopReg32,
    X86InsnKind::MovReg32Imm32,
    X86InsnKind::MovReg32Reg32,
    X86InsnKind::MovReg32Mem32,
    X86InsnKind::MovMem32Reg32,
    X86InsnKind::AddReg32Reg32,
    X86InsnKind::SubReg32Reg32,
    X86InsnKind::JmpRel8,
    X86InsnKind::JmpRel32,
    X86InsnKind::CallRel32,
    X86InsnKind::Ret,
];

const X86_REGS: &[Reg32] = &[
    Reg32::Eax,
    Reg32::Ecx,
    Reg32::Edx,
    Reg32::Ebx,
    Reg32::Esp,
    Reg32::Ebp,
    Reg32::Esi,
    Reg32::Edi,
];

const X86_INDEX_REGS: &[Reg32] = &[
    Reg32::Eax,
    Reg32::Ecx,
    Reg32::Edx,
    Reg32::Ebx,
    Reg32::Ebp,
    Reg32::Esi,
    Reg32::Edi,
];

impl X86AssemblyGenerator {
    fn random_register<R: MutRng>(rand: &mut R) -> Reg32 {
        X86_REGS[rand.below(X86_REGS.len())]
    }

    fn random_index_register<R: MutRng>(rand: &mut R) -> Reg32 {
        X86_INDEX_REGS[rand.below(X86_INDEX_REGS.len())]
    }

    fn random_scale<R: MutRng>(rand: &mut R) -> u32 {
        match rand.below(4) {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        }
    }

    fn random_mem_op<R: MutRng>(rand: &mut R) -> X86MemOp {
        match rand.below(5) {
            0 => X86MemOp::Base {
                base: Self::random_register(rand),
            },
            1 => X86MemOp::BaseDisp {
                base: Self::random_register(rand),
                disp: rand.next_u64() as i32,
            },
            2 => X86MemOp::BaseIndexScale {
                base: Self::random_register(rand),
                index: Self::random_index_register(rand),
                scale: Self::random_scale(rand),
            },
            3 => X86MemOp::BaseIndexScaleDisp {
                base: Self::random_register(rand),
                index: Self::random_index_register(rand),
                scale: Self::random_scale(rand),
                disp: rand.next_u64() as i32,
            },
            _ => X86MemOp::Absolute {
                addr: rand.next_u64() as u32,
            },
        }
    }

    fn random_insn<R: MutRng>(rand: &mut R) -> X86Insn {
        let kind = X86_KINDS[rand.below(X86_KINDS.len())];
        match kind {
            X86InsnKind::PushReg32 => X86Insn::PushReg32(Self::random_register(rand)),
            X86InsnKind::PopReg32 => X86Insn::PopReg32(Self::random_register(rand)),
            X86InsnKind::MovReg32Imm32 => {
                X86Insn::MovReg32Imm32(Self::random_register(rand), rand.next_u64() as u32)
            }
            X86InsnKind::MovReg32Reg32 => {
                X86Insn::MovReg32Reg32(Self::random_register(rand), Self::random_register(rand))
            }
            X86InsnKind::MovReg32Mem32 => {
                X86Insn::MovReg32Mem32(Self::random_register(rand), Self::random_mem_op(rand))
            }
            X86InsnKind::MovMem32Reg32 => {
                X86Insn::MovMem32Reg32(Self::random_mem_op(rand), Self::random_register(rand))
            }
            X86InsnKind::AddReg32Reg32 => {
                X86Insn::AddReg32Reg32(Self::random_register(rand), Self::random_register(rand))
            }
            X86InsnKind::SubReg32Reg32 => {
                X86Insn::SubReg32Reg32(Self::random_register(rand), Self::random_register(rand))
            }
            X86InsnKind::JmpRel8 => X86Insn::Branch(X86BranchInsn {
                kind: X86BranchKind::Jmp,
                width: X86BranchWidth::Rel8,
                target: random_short_branch_target(rand),
                displacement: None,
            }),
            X86InsnKind::JmpRel32 => X86Insn::Branch(X86BranchInsn {
                kind: X86BranchKind::Jmp,
                width: X86BranchWidth::Rel32,
                target: random_branch_target(rand),
                displacement: None,
            }),
            X86InsnKind::CallRel32 => X86Insn::Branch(X86BranchInsn {
                kind: X86BranchKind::Call,
                width: X86BranchWidth::Rel32,
                target: random_branch_target(rand),
                displacement: None,
            }),
            X86InsnKind::Ret => X86Insn::Ret,
        }
    }

    pub fn generate_block<R: MutRng>(
        rand: &mut R,
        n_instructions: usize,
    ) -> AbstractBlock<X86Insn> {
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
    ) -> Result<AbstractBlock<X86Insn>, Error> {
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
                let insn_size = X86Encoder::encoded_size(&insn, current_ip)?;
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
                "failed to generate an x86 block within max_size={max_size}"
            )));
        }

        Ok(AbstractBlock { insns: block })
    }

    pub fn resolve_branches<R: MutRng>(
        rand: &mut R,
        block: &mut AbstractBlock<X86Insn>,
        placement_context: &PlacementContext,
    ) -> Result<(), Error> {
        let mut insn_offsets = Vec::with_capacity(block.insns.len());
        let mut offset = 0_u64;
        for insn in &block.insns {
            insn_offsets.push(offset);
            offset +=
                X86Encoder::encoded_size(insn, placement_context.block_base_va + offset)? as u64;
        }

        let block_len = offset;
        let block_end_va = placement_context.block_base_va + block_len;

        for (index, insn) in block.insns.iter_mut().enumerate() {
            let X86Insn::Branch(branch) = insn else {
                continue;
            };

            let insn_offset = insn_offsets[index];
            let insn_ip = placement_context.block_base_va + insn_offset;
            let insn_len = X86Encoder::encoded_size(&X86Insn::Branch(*branch), insn_ip)? as u64;
            let next_ip = insn_ip + insn_len;
            let (min_displacement, max_displacement) = match branch.width {
                X86BranchWidth::Rel8 => (i8::MIN as i64, i8::MAX as i64),
                X86BranchWidth::Rel32 => (i32::MIN as i64, i32::MAX as i64),
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
                X86BranchWidth::Rel8 => {
                    if !(-128..=127).contains(&displacement) {
                        return Err(Error::illegal_argument(format!(
                            "resolved rel8 branch displacement out of range: {displacement}"
                        )));
                    }
                }
                X86BranchWidth::Rel32 => {
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
