pub mod common;
pub mod x64;
pub mod x86;

use crate::arch::{X86_64Insn, X86Insn};
use crate::core::rng::MutRng;
use crate::encoder::{x64::X64Encoder, x86::X86Encoder};
use crate::error::Error;
use crate::ir::{AbstractBlock, PlacementContext};
use crate::pe::CodeArch;

use self::{x64::X64AssemblyGenerator, x86::X86AssemblyGenerator};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblyBackend {
    X86,
    X64,
}

#[derive(Debug, Clone)]
pub enum AssemblyBlock {
    X86(AbstractBlock<X86Insn>),
    X64(AbstractBlock<X86_64Insn>),
}

impl AssemblyBackend {
    pub fn for_arch(arch: CodeArch) -> Option<Self> {
        match arch {
            CodeArch::X86 => Some(Self::X86),
            CodeArch::X64 => Some(Self::X64),
            CodeArch::Arm32 | CodeArch::Arm64 => None,
        }
    }

    pub fn generate_block<R: MutRng>(&self, rand: &mut R, n_instructions: usize) -> AssemblyBlock {
        match self {
            Self::X86 => {
                AssemblyBlock::X86(X86AssemblyGenerator::generate_block(rand, n_instructions))
            }
            Self::X64 => {
                AssemblyBlock::X64(X64AssemblyGenerator::generate_block(rand, n_instructions))
            }
        }
    }

    pub fn generate_block_max_size<R: MutRng>(
        &self,
        rand: &mut R,
        base_ip: u64,
        max_size: usize,
    ) -> Result<AssemblyBlock, Error> {
        match self {
            Self::X86 => X86AssemblyGenerator::generate_block_max_size(rand, base_ip, max_size)
                .map(AssemblyBlock::X86),
            Self::X64 => X64AssemblyGenerator::generate_block_max_size(rand, base_ip, max_size)
                .map(AssemblyBlock::X64),
        }
    }

    pub fn estimate_block_len(&self, block: &AssemblyBlock, base_ip: u64) -> Result<usize, Error> {
        match (self, block) {
            (Self::X86, AssemblyBlock::X86(block)) => {
                let mut total = 0_usize;
                let mut current_ip = base_ip;
                for insn in &block.insns {
                    let insn_len = X86Encoder::encoded_size(insn, current_ip)?;
                    total += insn_len;
                    current_ip += insn_len as u64;
                }
                Ok(total)
            }
            (Self::X64, AssemblyBlock::X64(block)) => {
                let mut total = 0_usize;
                let mut current_ip = base_ip;
                for insn in &block.insns {
                    let insn_len = X64Encoder::encoded_size(insn, current_ip)?;
                    total += insn_len;
                    current_ip += insn_len as u64;
                }
                Ok(total)
            }
            (Self::X86, AssemblyBlock::X64(_)) => Err(Error::illegal_argument(
                "attempted to use x86 assembly backend with an x64 block",
            )),
            (Self::X64, AssemblyBlock::X86(_)) => Err(Error::illegal_argument(
                "attempted to use x64 assembly backend with an x86 block",
            )),
        }
    }

    pub fn resolve_branches<R: MutRng>(
        &self,
        rand: &mut R,
        block: &mut AssemblyBlock,
        placement: &PlacementContext,
    ) -> Result<(), Error> {
        match (self, block) {
            (Self::X86, AssemblyBlock::X86(block)) => {
                X86AssemblyGenerator::resolve_branches(rand, block, placement)
            }
            (Self::X64, AssemblyBlock::X64(block)) => {
                X64AssemblyGenerator::resolve_branches(rand, block, placement)
            }
            (Self::X86, AssemblyBlock::X64(_)) => Err(Error::illegal_argument(
                "attempted to use x86 assembly backend with an x64 block",
            )),
            (Self::X64, AssemblyBlock::X86(_)) => Err(Error::illegal_argument(
                "attempted to use x64 assembly backend with an x86 block",
            )),
        }
    }

    pub fn encode_block(&self, block: &AssemblyBlock, base_ip: u64) -> Result<Vec<u8>, Error> {
        match (self, block) {
            (Self::X86, AssemblyBlock::X86(block)) => X86Encoder::encode_block(block, base_ip),
            (Self::X64, AssemblyBlock::X64(block)) => X64Encoder::encode_block(block, base_ip),
            (Self::X86, AssemblyBlock::X64(_)) => Err(Error::illegal_argument(
                "attempted to use x86 assembly backend with an x64 block",
            )),
            (Self::X64, AssemblyBlock::X86(_)) => Err(Error::illegal_argument(
                "attempted to use x64 assembly backend with an x86 block",
            )),
        }
    }
}
