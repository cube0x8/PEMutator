use crate::core::rng::MutRng;
use crate::mutations::budget::PeSizeBudget;
use crate::mutations::mutations::BudgetedMutation;
use crate::mutations::shared::RawMutationResult;
use crate::pe::{PeInput, PeSizeLimits};

pub struct OverlayMutations;

impl OverlayMutations {
    pub fn random_mutation<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        max_len: usize,
    ) -> RawMutationResult {
        let mut budget = match PeSizeBudget::from_input(input, PeSizeLimits::default()) {
            Ok(budget) => budget,
            Err(_) => return RawMutationResult::Skipped,
        };
        Self::random_mutation_with_budget(input, rng, max_len, &mut budget)
    }

    pub fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        max_len: usize,
        budget: &mut PeSizeBudget,
    ) -> RawMutationResult {
        match rng.below(5) {
            0 => {
                let _ = budget.try_resize_delta(input.overlay.len(), 0);
                input.overlay.clear();
            }
            1 => {
                let new_len = 4 + rng.below(0x28);
                if budget
                    .try_resize_delta(input.overlay.len(), new_len)
                    .is_err()
                {
                    return RawMutationResult::Skipped;
                }
                input.overlay.resize(new_len, 0);
            }
            2 => {
                let new_len = 0x2c + rng.below(0x7d5);
                if budget
                    .try_resize_delta(input.overlay.len(), new_len)
                    .is_err()
                {
                    return RawMutationResult::Skipped;
                }
                input.overlay.resize(new_len, 0);
            }
            3 => {
                let new_len = 0x801 + rng.below(max_len.max(0x802) - 0x801);
                if budget
                    .try_resize_delta(input.overlay.len(), new_len)
                    .is_err()
                {
                    return RawMutationResult::Skipped;
                }
                input.overlay.resize(new_len, 0);
            }
            _ => {
                if input.overlay.is_empty() {
                    if budget.try_resize_delta(0, 8).is_err() {
                        return RawMutationResult::Skipped;
                    }
                    input.overlay.resize(8, 0);
                }
                let mutation_count = 1 + rng.below(input.overlay.len());
                for _ in 0..mutation_count {
                    let index = rng.below(input.overlay.len());
                    input.overlay[index] = rng.next_u8();
                }
            }
        }

        RawMutationResult::Mutated
    }
}

impl BudgetedMutation for OverlayMutations {
    fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        budget: &mut PeSizeBudget,
    ) -> Result<RawMutationResult, crate::error::Error> {
        Ok(Self::random_mutation_with_budget(
            input,
            rng,
            budget.remaining_materialized_budget().unwrap_or(usize::MAX),
            budget,
        ))
    }
}
