use crate::assembly::AssemblyBackend;
use crate::core::rng::MutRng;
use crate::error::Error;
use crate::ir::PlacementContext;
use crate::mutations::budget::PeSizeBudget;
use crate::mutations::mutations::BudgetedMutation;
use crate::mutations::shared::{RawMutationResult, is_executable_section};
use crate::pe::{
    DATA_SECTION_NAMES, EXEC_SECTION_NAMES, IMAGE_SCN_MEM_EXECUTE, PeInput, PeSection,
    PeSizeLimits,
};

pub struct SectionCountMutations;

impl SectionCountMutations {
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
        if input.sections.len() <= 1 || rng.coinflip(0.6) {
            let backend = input.infer_code_arch().and_then(AssemblyBackend::for_arch);
            let characteristics = if rng.coinflip(0.5) {
                0x6000_0020
            } else {
                0xc000_0040
            };
            let is_exec = has_execute_characteristic(characteristics);
            let name_pool = if is_exec {
                &EXEC_SECTION_NAMES[..]
            } else {
                &DATA_SECTION_NAMES[..]
            };
            let name = name_pool[rng.below(name_pool.len())];
            let raw_data = if is_exec {
                generate_exec_section_body(rng, backend)?
            } else {
                generate_random_section_body(rng)
            };
            if budget.try_resize_delta(0, raw_data.len()).is_err() {
                return Ok(RawMutationResult::Skipped);
            }
            let new_section = PeSection::new(name, 0, raw_data, characteristics);
            let insert_at = rng.below(input.sections.len() + 1);
            input.sections.insert(insert_at, new_section);
        } else {
            let index = rng.below(input.sections.len());
            let removed = input.sections.remove(index);
            let _ = budget.try_resize_delta(removed.raw_data.len(), 0);
            if input.entry_section_index().is_none() && !input.sections.is_empty() {
                if let Some(section) = input
                    .sections
                    .iter()
                    .find(|section| is_executable_section(section))
                {
                    if input
                        .set_entry_point_with_budget(section.virtual_address, budget)
                        .is_err()
                    {
                        return Ok(RawMutationResult::Skipped);
                    }
                } else {
                    let index = rng.below(input.sections.len());
                    let entry_point = input.sections[index].virtual_address;
                    if input
                        .set_entry_point_with_budget(entry_point, budget)
                        .is_err()
                    {
                        return Ok(RawMutationResult::Skipped);
                    }
                }
            }
        }

        Ok(RawMutationResult::Mutated)
    }
}

impl BudgetedMutation for SectionCountMutations {
    fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        budget: &mut PeSizeBudget,
    ) -> Result<RawMutationResult, Error> {
        Self::random_mutation_with_budget(input, rng, budget)
    }
}

fn has_execute_characteristic(characteristics: u32) -> bool {
    (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
}

fn generate_exec_section_body<R: MutRng>(
    rng: &mut R,
    backend: Option<AssemblyBackend>,
) -> Result<Vec<u8>, Error> {
    let max_len = 4 + rng.below(29);
    let Some(backend) = backend else {
        return Ok(vec![0x90; max_len.saturating_sub(1)]
            .into_iter()
            .chain([0xc3])
            .collect());
    };

    let mut block = match backend.generate_block_max_size(rng, 0, max_len) {
        Ok(block) => block,
        Err(_) => {
            return Ok(vec![0x90; max_len.saturating_sub(1)]
                .into_iter()
                .chain([0xc3])
                .collect());
        }
    };
    let placement = PlacementContext {
        raw_offset: 0,
        block_base_va: 0,
        section_start_va: 0,
        section_end_va: max_len as u64,
    };
    backend.resolve_branches(rng, &mut block, &placement)?;
    let mut block_bytes = backend.encode_block(&block, 0)?;
    debug_assert!(block_bytes.len() <= max_len);
    block_bytes.resize(max_len, 0x90);
    Ok(block_bytes)
}

fn generate_random_section_body<R: MutRng>(rng: &mut R) -> Vec<u8> {
    let len = 4 + rng.below(29);
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        bytes.push(rng.next_u8());
    }
    bytes
}
