use crate::core::rng::MutRng;
use crate::mutations::helper::{
    huge_directory_size, overflowing_section_size, slightly_oversized_for_section,
};
use crate::mutations::mutations::InPlaceMutation;
use crate::mutations::rva::{
    mutate_controlled_invalid_rva, mutate_havoc_rva, mutate_plausible_rva,
};
use crate::mutations::shared::RawMutationResult;
use crate::pe::PeInput;
use crate::pe::data_directories::export::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_EXPORT_DIRECTORY_LEN,
};
use crate::pe::{find_section_containing_rva, pick_random_section, section_span};

pub struct DataDirectoryEntryMutations;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectoryEntryMutationOutcome {
    pub result: RawMutationResult,
    pub touched_export_directory: bool,
}

const PLAUSIBLE_WEIGHT: usize = 5;
const CONTROLLED_INVALID_WEIGHT: usize = 3;
const HAVOC_WEIGHT: usize = 2;
const SMALL_SIZE_VALUES: [u32; 3] = [0x20, 0x40, 0x80];
const ALIGNED_SIZE_VALUES: [u32; 2] = [0x100, 0x200];

impl DataDirectoryEntryMutations {
    pub fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
        Self::random_mutation_with_outcome(input, rng).result
    }

    pub fn random_mutation_with_outcome<R: MutRng>(
        input: &mut PeInput,
        rng: &mut R,
    ) -> DataDirectoryEntryMutationOutcome {
        if input.data_directories.is_empty() {
            return DataDirectoryEntryMutationOutcome {
                result: RawMutationResult::Skipped,
                touched_export_directory: false,
            };
        }

        let index = rng.below(input.data_directories.len());
        let bucket = rng.below(PLAUSIBLE_WEIGHT + CONTROLLED_INVALID_WEIGHT + HAVOC_WEIGHT);

        if bucket < PLAUSIBLE_WEIGHT {
            mutate_plausible(input, rng, index);
        } else if bucket < PLAUSIBLE_WEIGHT + CONTROLLED_INVALID_WEIGHT {
            mutate_controlled_invalid(input, rng, index);
        } else {
            mutate_havoc(input, rng, index);
        }

        DataDirectoryEntryMutationOutcome {
            result: RawMutationResult::Mutated,
            touched_export_directory: index == IMAGE_DIRECTORY_ENTRY_EXPORT,
        }
    }
}

impl InPlaceMutation for DataDirectoryEntryMutations {
    fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
        Self::random_mutation(input, rng)
    }
}

fn mutate_plausible<R: MutRng>(input: &mut PeInput, rng: &mut R, index: usize) {
    let current_rva = input.data_directories[index].virtual_address;
    let new_rva = mutate_plausible_rva(current_rva, &input.sections, rng);

    input.data_directories[index].virtual_address = new_rva;

    let section_for_size = find_section_containing_rva(&input.sections, new_rva)
        .or_else(|| pick_random_section(&input.sections, rng));
    let new_size = match rng.below(6) {
        0 => 0,
        1 => 1,
        2 => canonical_directory_size(index, input.data_directories[index].size),
        3 => SMALL_SIZE_VALUES[rng.below(SMALL_SIZE_VALUES.len())],
        4 => ALIGNED_SIZE_VALUES[rng.below(ALIGNED_SIZE_VALUES.len())],
        _ => slightly_oversized_for_section(
            section_for_size,
            rng,
            input.data_directories[index].size,
        ),
    };

    input.data_directories[index].size = new_size;
}

fn mutate_controlled_invalid<R: MutRng>(input: &mut PeInput, rng: &mut R, index: usize) {
    match rng.below(7) {
        0 => {
            input.data_directories[index].virtual_address =
                mutate_controlled_invalid_rva(&input.sections, rng);
        }
        1 => {
            input.data_directories[index].size = huge_directory_size(rng);
        }
        2 => {
            let section = find_section_containing_rva(
                &input.sections,
                input.data_directories[index].virtual_address,
            )
            .or_else(|| pick_random_section(&input.sections, rng));
            input.data_directories[index].size =
                overflowing_section_size(section, rng, input.data_directories[index].size);
        }
        _ => {
            let section = pick_random_section(&input.sections, rng);
            if let Some(section) = section {
                let span = section_span(section);
                let overrun = if rng.coinflip(0.6) {
                    1 + rng.below(0x40) as u32
                } else {
                    0x200 + rng.below(0x1000) as u32
                };
                let base = section
                    .virtual_address
                    .saturating_add(span.saturating_sub(1 + rng.below(0x20) as u32));
                input.data_directories[index].virtual_address = base;
                input.data_directories[index].size = overrun.max(1);
            } else {
                input.data_directories[index].virtual_address = rng.below(0x20_000) as u32;
                input.data_directories[index].size = 0x1000 + rng.below(0x4000) as u32;
            }
        }
    }
}

fn mutate_havoc<R: MutRng>(input: &mut PeInput, rng: &mut R, index: usize) {
    input.data_directories[index].virtual_address = mutate_havoc_rva(rng);
    input.data_directories[index].size = rng.next_u64() as u32;
}

fn canonical_directory_size(index: usize, current_size: u32) -> u32 {
    match index {
        IMAGE_DIRECTORY_ENTRY_EXPORT => IMAGE_EXPORT_DIRECTORY_LEN as u32,
        _ => current_size.max(0x20),
    }
}
