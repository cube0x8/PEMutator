use crate::MutRng;
use crate::error::Error;
use crate::mutations::budget::PeSizeBudget;
use crate::mutations::mutations::BudgetedMutation;
use crate::mutations::shared::{
    ExecutableChunkMutationPlan, RawMutationResult, is_executable_section,
};
use crate::pe::PeInput;
use crate::pe::PeSizeLimits;
use asm_mutator_core::assembly::{AssemblyArch, AssemblyBackend};
use asm_mutator_core::ir::PlacementContext;

pub struct ExecutableChunkAssemblyMutations;

pub fn plan_executable_chunk_assembly_mutation<R: MutRng>(
    rng: &mut R,
    input: &PeInput,
) -> Result<Option<ExecutableChunkMutationPlan>, Error> {
    let Some(code_arch) = input.infer_code_arch() else {
        return Ok(None);
    };
    let assembly_arch = match code_arch {
        crate::pe::CodeArch::X86 => AssemblyArch::X86,
        crate::pe::CodeArch::X64 => AssemblyArch::X64,
        crate::pe::CodeArch::Arm32 => AssemblyArch::Arm32,
        crate::pe::CodeArch::Arm64 => AssemblyArch::Arm64,
    };
    let Some(backend) = AssemblyBackend::for_arch(assembly_arch) else {
        return Ok(None);
    };

    let executable_sections: Vec<usize> = input
        .sections
        .iter()
        .enumerate()
        .filter_map(|(index, section)| is_executable_section(section).then_some(index))
        .collect();
    if executable_sections.is_empty() {
        return Ok(None);
    }

    let section_index = executable_sections[rng.below(executable_sections.len())];
    let section = &input.sections[section_index];
    if section.raw_data.is_empty() {
        return Ok(None);
    }

    let max_chunk_len = section.raw_data.len().min(32);
    let chunk_len = 1 + rng.below(max_chunk_len);
    let chunk_offset = rng.below(section.raw_data.len().saturating_sub(chunk_len) + 1);

    let section_span = (section.virtual_size.max(section.raw_data.len() as u32)) as usize;
    let placement = PlacementContext {
        raw_offset: chunk_offset,
        block_base_va: section.virtual_address as u64 + chunk_offset as u64,
        section_start_va: section.virtual_address as u64,
        section_end_va: section.virtual_address as u64 + section_span as u64,
    };

    let mut block = match backend.generate_block_max_size(rng, placement.block_base_va, chunk_len) {
        Ok(block) => block,
        Err(_) => return Ok(None),
    };
    backend.resolve_branches(rng, &mut block, &placement)?;
    let encoded_bytes = backend.encode_block(&block, placement.block_base_va)?;
    debug_assert!(encoded_bytes.len() <= chunk_len);
    let encoded_len = encoded_bytes.len();
    let mut block_bytes = encoded_bytes;
    block_bytes.resize(chunk_len, 0x90);

    Ok(Some(ExecutableChunkMutationPlan {
        backend,
        section_index,
        chunk_offset,
        chunk_len,
        placement,
        block,
        encoded_len,
        block_bytes,
    }))
}

impl ExecutableChunkAssemblyMutations {
    pub fn random_mutation<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
    ) -> Result<RawMutationResult, Error> {
        let mut budget = PeSizeBudget::from_input(input, PeSizeLimits::default())?;
        Self::random_mutation_with_budget(input, rng, &mut budget)
    }

    pub fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        budget: &mut PeSizeBudget,
    ) -> Result<RawMutationResult, Error> {
        let Some(plan) = plan_executable_chunk_assembly_mutation(rng, input)? else {
            return Ok(RawMutationResult::Skipped);
        };

        let section = &mut input.sections[plan.section_index];
        let chunk_end = plan.chunk_offset + plan.chunk_len;
        if section.raw_data.len() < chunk_end {
            if budget
                .try_resize_delta(section.raw_data.len(), chunk_end)
                .is_err()
            {
                return Ok(RawMutationResult::Skipped);
            }
            section.raw_data.resize(chunk_end, 0x90);
        }
        section.raw_data[plan.chunk_offset..chunk_end].copy_from_slice(&plan.block_bytes);
        section.virtual_size = section.virtual_size.max(chunk_end as u32);
        Ok(RawMutationResult::Mutated)
    }
}

impl BudgetedMutation for ExecutableChunkAssemblyMutations {
    fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        budget: &mut PeSizeBudget,
    ) -> Result<RawMutationResult, Error> {
        Self::random_mutation_with_budget(input, rng, budget)
    }
}
