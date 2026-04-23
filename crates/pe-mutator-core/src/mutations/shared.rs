use crate::assembly::AssemblyBackend;
use crate::assembly::AssemblyBlock;
use crate::ir::PlacementContext;
use crate::pe::PeSection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawMutationResult {
    Mutated,
    Skipped,
}

#[derive(Debug, Clone)]
pub struct ExecutableChunkMutationPlan {
    pub backend: AssemblyBackend,
    pub section_index: usize,
    pub chunk_offset: usize,
    pub chunk_len: usize,
    pub placement: PlacementContext,
    pub block: AssemblyBlock,
    pub encoded_len: usize,
    pub block_bytes: Vec<u8>,
}

pub(crate) fn is_executable_section(section: &PeSection) -> bool {
    section.name_string() == ".text" || (section.characteristics & 0x2000_0000) != 0
}
