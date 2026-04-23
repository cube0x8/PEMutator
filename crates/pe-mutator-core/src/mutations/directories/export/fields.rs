use crate::core::io::write_u32_into;
use crate::core::rng::MutRng;
use crate::mutations::rva::{
    mutate_controlled_invalid_rva, mutate_havoc_rva, mutate_plausible_rva,
};
use crate::mutations::shared::RawMutationResult;
use crate::pe::PeInput;
use crate::pe::data_directories::export::{IMAGE_DIRECTORY_ENTRY_EXPORT, current_name_pointer_rva};
use crate::pe::sections::find_section_containing_rva_mut;

const PLAUSIBLE_WEIGHT: usize = 5;
const CONTROLLED_INVALID_WEIGHT: usize = 3;
const HAVOC_WEIGHT: usize = 2;
const ORDINAL_BASE_OFFSET: usize = 16;
const ADDRESS_TABLE_ENTRIES_OFFSET: usize = 20;
const NUMBER_OF_NAME_POINTERS_OFFSET: usize = 24;
const NAME_POINTER_RVA_OFFSET: usize = 32;

// Mutates core export count fields and ordinal_base with u32 values biased toward edge cases.
pub(super) fn mutate_count_and_relations<R: MutRng>(
    input: &mut PeInput,
    rng: &mut R,
) -> RawMutationResult {
    let Some(export) = input.export_directory.as_ref() else {
        return RawMutationResult::Skipped;
    };

    let (field_offset, new_value) = match rng.below(3) {
        0 => (
            NUMBER_OF_NAME_POINTERS_OFFSET,
            pick_special_u32_value(
                export.number_of_name_pointers,
                export.address_table_entries,
                rng,
            ),
        ),
        1 => (
            ADDRESS_TABLE_ENTRIES_OFFSET,
            pick_special_u32_value(
                export.address_table_entries,
                export.number_of_name_pointers,
                rng,
            ),
        ),
        _ => (
            ORDINAL_BASE_OFFSET,
            pick_special_u32_value(export.ordinal_base, export.address_table_entries, rng),
        ),
    };

    if !patch_export_u32_field(input, field_offset, new_value) {
        return RawMutationResult::Skipped;
    }

    if let Some(export) = input.export_directory.as_mut() {
        match field_offset {
            NUMBER_OF_NAME_POINTERS_OFFSET => export.number_of_name_pointers = new_value,
            ADDRESS_TABLE_ENTRIES_OFFSET => export.address_table_entries = new_value,
            ORDINAL_BASE_OFFSET => export.ordinal_base = new_value,
            _ => {}
        }
    }

    RawMutationResult::Mutated
}

// Mutates the export name pointer table RVA with plausible or invalid targets.
pub(super) fn mutate_rva_locator_fields<R: MutRng>(
    input: &mut PeInput,
    rng: &mut R,
) -> RawMutationResult {
    let Some(current_rva) = current_name_pointer_rva(input.export_directory.as_ref()) else {
        return RawMutationResult::Skipped;
    };

    let bucket = rng.below(PLAUSIBLE_WEIGHT + CONTROLLED_INVALID_WEIGHT + HAVOC_WEIGHT);
    let new_rva = if bucket < PLAUSIBLE_WEIGHT {
        mutate_plausible_rva(current_rva, &input.sections, rng)
    } else if bucket < PLAUSIBLE_WEIGHT + CONTROLLED_INVALID_WEIGHT {
        mutate_controlled_invalid_rva(&input.sections, rng)
    } else {
        mutate_havoc_rva(rng)
    };

    if !patch_name_pointer_rva(input, new_rva) {
        return RawMutationResult::Skipped;
    }

    if let Some(export) = input.export_directory.as_mut() {
        export.name_pointer_rva = new_rva;
    }

    RawMutationResult::Mutated
}

// Reserved for mutations of export timestamps, versions, and flag-like fields.
pub(super) fn mutate_version_timestamp_and_flags<R: MutRng>(
    _input: &mut PeInput,
    _rng: &mut R,
) -> RawMutationResult {
    RawMutationResult::Skipped
}

fn patch_name_pointer_rva(input: &mut PeInput, new_rva: u32) -> bool {
    patch_export_u32_field(input, NAME_POINTER_RVA_OFFSET, new_rva)
}

fn patch_export_u32_field(input: &mut PeInput, field_offset: usize, new_value: u32) -> bool {
    let Some(directory) = input.data_directories.get(IMAGE_DIRECTORY_ENTRY_EXPORT) else {
        return false;
    };
    if directory.virtual_address == 0 {
        return false;
    }

    let export_rva = directory.virtual_address;
    let Some(section) = find_section_containing_rva_mut(&mut input.sections, export_rva) else {
        return false;
    };

    let Some(relative) = export_rva.checked_sub(section.virtual_address) else {
        return false;
    };
    let start = relative as usize;
    let Some(field_start) = start.checked_add(field_offset) else {
        return false;
    };
    let Some(field_end) = field_start.checked_add(4) else {
        return false;
    };
    if field_end > section.raw_data.len() {
        return false;
    }

    write_u32_into(&mut section.raw_data, field_start, new_value);
    true
}

fn pick_special_u32_value<R: MutRng>(current: u32, related: u32, rng: &mut R) -> u32 {
    if rng.coinflip(0.2) {
        return rng.next_u64() as u32;
    }

    match rng.below(12) {
        0 => 0,
        1 => 1,
        2 => u32::MAX,
        3 => u32::MAX - 1,
        4 => current.wrapping_add(1),
        5 => current.wrapping_sub(1),
        6 => related,
        7 => related.wrapping_add(1),
        8 => related.wrapping_sub(1),
        9 => 0x7fff_ffff,
        10 => 0x8000_0000,
        _ => rng.below(0x1_0000) as u32,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::core::SimpleRng;
    use crate::mutations::shared::RawMutationResult;
    use crate::pe::PeInput;

    use super::mutate_rva_locator_fields;

    mod test_util {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/common/mod.rs"));
    }

    #[test]
    fn mutate_rva_locator_fields_rewrites_name_pointer_rva_on_mmc() {
        let bytes = fs::read(test_util::sample_path("mmc.exe")).unwrap();
        let original = PeInput::parse(&bytes).unwrap();
        let original_export = original
            .export_directory
            .clone()
            .expect("mmc.exe should expose a parsed export directory");

        assert_eq!(
            original_export.number_of_name_pointers, 1,
            "test fixture assumption changed: mmc.exe should have a single export name pointer"
        );

        let mut successful_mutation = None;

        for seed in 1_u64..2048 {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            let result = mutate_rva_locator_fields(&mut candidate, &mut rng);
            if result != RawMutationResult::Mutated {
                continue;
            }

            let mutated_in_memory = candidate
                .export_directory
                .clone()
                .expect("export mutation should keep export metadata available");
            if mutated_in_memory.name_pointer_rva == original_export.name_pointer_rva {
                continue;
            }

            let reparsed = PeInput::parse(&candidate.to_bytes().unwrap()).unwrap();
            let reparsed_export = reparsed
                .export_directory
                .clone()
                .expect("mutated file should still expose an export directory");

            if reparsed_export.name_pointer_rva == original_export.name_pointer_rva {
                continue;
            }

            successful_mutation = Some((seed, mutated_in_memory, reparsed_export));
            break;
        }

        let (seed, mutated_in_memory, reparsed_export) = successful_mutation
            .expect("expected at least one seed to mutate mmc.exe export name_pointer_rva");

        assert_eq!(
            reparsed_export.name_pointer_rva, mutated_in_memory.name_pointer_rva,
            "seed {seed} mutated the in-memory export directory but did not persist to bytes"
        );
        assert_ne!(
            reparsed_export.name_pointer_rva, original_export.name_pointer_rva,
            "seed {seed} should change mmc.exe name_pointer_rva"
        );
        assert_eq!(reparsed_export.number_of_name_pointers, 1);
    }
}
