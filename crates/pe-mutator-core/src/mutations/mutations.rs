use crate::core::rng::MutRng;
use crate::error::Error;
use crate::mutations::budget::PeSizeBudget;
use crate::mutations::shared::RawMutationResult;
use crate::pe::{PeInput, PeSizeLimits};

pub trait InPlaceMutation {
    fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult;
}

pub trait BudgetedMutation {
    fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        budget: &mut PeSizeBudget,
    ) -> Result<RawMutationResult, Error>;

    fn random_mutation<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
    ) -> Result<RawMutationResult, Error> {
        let mut budget = PeSizeBudget::from_input(input, PeSizeLimits::default())?;
        Self::random_mutation_with_budget(input, rng, &mut budget)
    }
}
