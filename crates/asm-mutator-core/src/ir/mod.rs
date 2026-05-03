pub mod x64;
pub mod x86;

pub use x64::*;
pub use x86::*;

#[derive(Debug, Clone)]
pub struct AbstractBlock<I> {
    pub insns: Vec<I>,
}

#[derive(Debug, Clone)]
pub struct PlacedBlock {
    pub raw_offset: usize,
    pub virtual_address: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct CodeGenContext {
    pub section_va: u64,
    pub section_raw_len: usize,
    pub min_block_offset: usize,
    pub max_block_offset: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct PlacementContext {
    pub raw_offset: usize,
    pub block_base_va: u64,
    pub section_start_va: u64,
    pub section_end_va: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum BranchTarget {
    IntraBlockForward,
    IntraBlockBackward,
    RandomInBlock,
    RandomInSection,
    AbsoluteVa(u64),
}
