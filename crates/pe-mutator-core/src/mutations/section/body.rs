use crate::core::rng::MutRng;
use crate::error::Error;
use crate::mutations::budget::PeSizeBudget;
use crate::mutations::mutations::BudgetedMutation;
use crate::mutations::shared::RawMutationResult;
use crate::pe::{PeInput, PeSizeLimits};

pub struct SectionBodyMutations;

impl SectionBodyMutations {
    pub fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
        let mut budget = match PeSizeBudget::from_input(input, PeSizeLimits::default()) {
            Ok(budget) => budget,
            Err(_) => return RawMutationResult::Skipped,
        };
        Self::random_mutation_with_budget(input, rng, &mut budget)
    }

    pub fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        budget: &mut PeSizeBudget,
    ) -> RawMutationResult {
        if input.sections.is_empty() {
            return RawMutationResult::Skipped;
        }

        let index = rng.below(input.sections.len());
        let section = &mut input.sections[index];

        match rng.below(3) {
            // Flip a single random bit in the existing section bytes.
            0 if !section.raw_data.is_empty() => {
                let offset = rng.below(section.raw_data.len());
                section.raw_data[offset] ^= 1 << (rng.below(8) as u8);
            }
            // Append a short run of the same random byte to grow the section.
            1 => {
                let value = rng.next_u8();
                let count = 1 + rng.below(8);
                if budget
                    .try_resize_delta(
                        section.raw_data.len(),
                        section.raw_data.len().saturating_add(count),
                    )
                    .is_err()
                {
                    return RawMutationResult::Skipped;
                }
                section.raw_data.extend(std::iter::repeat_n(value, count));
            }
            // Truncate a small suffix while keeping at least one byte.
            2 if section.raw_data.len() > 1 => {
                let shrink = 1 + rng.below(section.raw_data.len().min(8));
                let new_len = section.raw_data.len().saturating_sub(shrink).max(1);
                let _ = budget.try_resize_delta(section.raw_data.len(), new_len);
                section.raw_data.truncate(new_len);
            }
            // Overwrite a few random positions in place with fresh random bytes.
            _ => {
                if section.raw_data.is_empty() {
                    return RawMutationResult::Skipped;
                }
                let mutation_count = 1 + rng.below(section.raw_data.len().min(8));
                for _ in 0..mutation_count {
                    let offset = rng.below(section.raw_data.len());
                    section.raw_data[offset] = rng.next_u8();
                }
            }
        }

        section.declared_size_of_raw_data = section.raw_data.len() as u32;
        section.virtual_size = section.virtual_size.max(section.raw_data.len() as u32);
        RawMutationResult::Mutated
    }
}

impl BudgetedMutation for SectionBodyMutations {
    fn random_mutation_with_budget<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
        budget: &mut PeSizeBudget,
    ) -> Result<RawMutationResult, Error> {
        Ok(Self::random_mutation_with_budget(input, rng, budget))
    }
}
