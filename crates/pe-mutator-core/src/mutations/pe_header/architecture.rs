use crate::MutRng;
use crate::error::Error;
use crate::mutations::budget::PeSizeBudget;
use crate::mutations::mutations::BudgetedMutation;
use crate::mutations::shared::RawMutationResult;
use crate::pe::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_I386, PeInput, PeSizeLimits, canonical_optional_header_size,
    expected_optional_magic,
};

pub struct ArchitectureMutations;

impl ArchitectureMutations {
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
        let machines = [
            IMAGE_FILE_MACHINE_I386,
            IMAGE_FILE_MACHINE_ARMNT,
            IMAGE_FILE_MACHINE_AMD64,
            IMAGE_FILE_MACHINE_ARM64,
        ];
        input.machine = machines[rng.below(machines.len())];
        input.set_optional_magic_with_budget(expected_optional_magic(input.machine), budget)?;
        input.declared_optional_header_size = canonical_optional_header_size(input.machine) as u16;
        input.ensure_coherent_architecture_with_budget(budget)?;

        Ok(RawMutationResult::Mutated)
    }
}

impl BudgetedMutation for ArchitectureMutations {
    fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        budget: &mut PeSizeBudget,
    ) -> Result<RawMutationResult, Error> {
        Self::random_mutation_with_budget(input, rng, budget)
    }
}
