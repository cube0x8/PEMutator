use crate::MutRng;
use crate::error::Error;
use crate::mutations::budget::PeSizeBudget;
use crate::mutations::mutations::BudgetedMutation;
use crate::mutations::shared::RawMutationResult;
use crate::pe::PeInput;
use crate::pe::PeSizeLimits;
use asm_mutator_core::assembly::{AssemblyArch, AssemblyBackend};
use asm_mutator_core::ir::PlacementContext;

pub struct EntryPointMutations;

impl EntryPointMutations {
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
        if input.sections.is_empty() {
            return Ok(RawMutationResult::Skipped);
        }

        let Some(code_arch) = input.infer_code_arch() else {
            return Ok(RawMutationResult::Skipped);
        };
        let assembly_arch = match code_arch {
            crate::pe::CodeArch::X86 => AssemblyArch::X86,
            crate::pe::CodeArch::X64 => AssemblyArch::X64,
            crate::pe::CodeArch::Arm32 => AssemblyArch::Arm32,
            crate::pe::CodeArch::Arm64 => AssemblyArch::Arm64,
        };
        let Some(backend) = AssemblyBackend::for_arch(assembly_arch) else {
            return Ok(RawMutationResult::Skipped);
        };

        let original_entry_point = input.entry_point();
        let index = input
            .entry_section_index()
            .unwrap_or_else(|| rng.below(input.sections.len()));
        let section = &mut input.sections[index];

        let n_instructions = 2 + rng.below(5);
        let mut block = backend.generate_block(rng, n_instructions);

        let section_span = (section.virtual_size.max(section.raw_data.len() as u32)) as usize;
        let materialized_span = section.raw_data.len();
        let entry_offset = original_entry_point
            .checked_sub(section.virtual_address)
            .map(|offset| offset as usize)
            .filter(|offset| *offset <= materialized_span);
        let provisional_base_ip = entry_offset
            .map(|offset| section.virtual_address as u64 + offset as u64)
            .unwrap_or(section.virtual_address as u64);
        let estimated_block_len = backend.estimate_block_len(&block, provisional_base_ip)?;

        let placement_offset = if let Some(entry_offset) = entry_offset {
            entry_offset
        } else {
            let max_offset = materialized_span
                .saturating_sub(estimated_block_len)
                .min(32);
            rng.below(max_offset + 1)
        };

        let section_end_va = section.virtual_address as u64
            + section_span.max(placement_offset + estimated_block_len) as u64;
        let placement = PlacementContext {
            raw_offset: placement_offset,
            block_base_va: section.virtual_address as u64 + placement_offset as u64,
            section_start_va: section.virtual_address as u64,
            section_end_va,
        };

        backend.resolve_branches(rng, &mut block, &placement)?;
        let block_bytes = backend.encode_block(&block, placement.block_base_va)?;

        let write_end = placement_offset + block_bytes.len();
        if section.raw_data.len() < write_end {
            if budget
                .try_resize_delta(section.raw_data.len(), write_end)
                .is_err()
            {
                return Ok(RawMutationResult::Skipped);
            }
            section.raw_data.resize(write_end, 0x90);
        }
        section.raw_data[placement_offset..write_end].copy_from_slice(&block_bytes);
        section.virtual_size = section.virtual_size.max(write_end as u32);

        let new_entry_point = entry_offset
            .map(|_| original_entry_point)
            .unwrap_or(placement.block_base_va as u32);
        input.set_entry_point_with_budget(new_entry_point, budget)?;
        Ok(RawMutationResult::Mutated)
    }
}

impl BudgetedMutation for EntryPointMutations {
    fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        budget: &mut PeSizeBudget,
    ) -> Result<RawMutationResult, Error> {
        Self::random_mutation_with_budget(input, rng, budget)
    }
}
