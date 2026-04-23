use crate::core::io::write_u16_into;
use crate::core::rng::MutRng;
use crate::pe::PeInput;
use crate::pe::data_directories::export::MAX_MUTATION_EXPORT_ORDINAL_TABLE_ENTRIES;
use crate::pe::data_directories::read_ordinal_table_entry;
use crate::pe::sections::find_section_containing_rva_mut;

pub(super) fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    match rng.below(5) {
        0 => mutate_ordinals(input, rng),
        1 => mutate_all_ordinals_equal(input, rng),
        2 => mutate_partial_duplicate_ordinals(input, rng),
        3 => mutate_descending_ordinal_run(input, rng),
        _ => mutate_shuffle_ordinal_order(input, rng),
    }
}

// Mutates one ordinal table WORD.
fn mutate_ordinals<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count == 0 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_ORDINAL_TABLE_ENTRIES {
        return false;
    }

    let table_rva = export.ordinal_table_rva;
    let index = rng.below(count);
    if read_ordinal_table_entry(&input.sections, table_rva, index).is_none() {
        return false;
    }

    let new_value = pick_base_ordinal_value(export.address_table_entries, rng);

    patch_ordinal_table_entry(input, table_rva, index, new_value)
}

// Replaces every ordinal table WORD with the same base-case value.
fn mutate_all_ordinals_equal<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count == 0 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_ORDINAL_TABLE_ENTRIES {
        return false;
    }

    let table_rva = export.ordinal_table_rva;
    let new_value = pick_base_ordinal_value(export.address_table_entries, rng);
    let mut mutated = false;

    for index in 0..count {
        if !patch_ordinal_table_entry(input, table_rva, index, new_value) {
            return mutated;
        }
        mutated = true;
    }

    mutated
}

// Copies one ordinal value into a subset of other entries, creating controlled duplicates.
fn mutate_partial_duplicate_ordinals<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count < 2 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_ORDINAL_TABLE_ENTRIES {
        return false;
    }

    let table_rva = export.ordinal_table_rva;
    let source_index = rng.below(count);
    let Some(source_value) = read_ordinal_table_entry(&input.sections, table_rva, source_index)
    else {
        return false;
    };

    let duplicate_count = 1 + rng.below(count - 1);
    let start = rng.below(count - duplicate_count + 1);
    let mut mutated = false;

    for index in start..start + duplicate_count {
        if index == source_index {
            continue;
        }
        if !patch_ordinal_table_entry(input, table_rva, index, source_value) {
            return mutated;
        }
        mutated = true;
    }

    if mutated {
        return true;
    }

    let mut target_index = rng.below(count - 1);
    if target_index >= source_index {
        target_index += 1;
    }
    patch_ordinal_table_entry(input, table_rva, target_index, source_value)
}

// Replaces a contiguous subset with a descending WORD sequence.
fn mutate_descending_ordinal_run<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count < 2 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_ORDINAL_TABLE_ENTRIES {
        return false;
    }

    let table_rva = export.ordinal_table_rva;
    let start = rng.below(count - 1);
    let len = 2 + rng.below(count - start - 1);
    let max_start = u16::MAX.saturating_sub((len - 1) as u16);
    let start_value = if max_start == 0 {
        0
    } else {
        rng.below(max_start as usize + 1) as u16
    }
    .saturating_add((len - 1) as u16);

    let mut mutated = false;
    for offset in 0..len {
        let value = start_value.saturating_sub(offset as u16);
        if !patch_ordinal_table_entry(input, table_rva, start + offset, value) {
            return mutated;
        }
        mutated = true;
    }

    mutated
}

// Shuffles a contiguous run of ordinal table WORDs to disorder their current ordering.
fn mutate_shuffle_ordinal_order<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count < 2 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_ORDINAL_TABLE_ENTRIES {
        return false;
    }

    let table_rva = export.ordinal_table_rva;
    let start = rng.below(count - 1);
    let len = 2 + rng.below(count - start - 1);
    let mut values = Vec::with_capacity(len);

    for index in start..start + len {
        let Some(value) = read_ordinal_table_entry(&input.sections, table_rva, index) else {
            return false;
        };
        values.push(value);
    }

    shuffle_values(&mut values, rng);
    if values.windows(2).all(|window| window[0] == window[1]) {
        return false;
    }

    let mut mutated = false;
    for (offset, value) in values.into_iter().enumerate() {
        if !patch_ordinal_table_entry(input, table_rva, start + offset, value) {
            return mutated;
        }
        mutated = true;
    }

    mutated
}

fn pick_base_ordinal_value<R: MutRng>(address_table_entries: u32, rng: &mut R) -> u16 {
    match rng.below(7) {
        0 => 0,
        1 => 1,
        2 => address_table_entries.saturating_sub(1).min(u16::MAX as u32) as u16,
        3 => address_table_entries.min(u16::MAX as u32) as u16,
        4 => u16::MAX,
        5 => rng.below(0x100) as u16,
        _ => 0xff00_u16.saturating_add(rng.below(0x100) as u16),
    }
}

fn shuffle_values<R: MutRng>(values: &mut [u16], rng: &mut R) {
    if values.len() < 2 {
        return;
    }

    let original = values.to_vec();
    for index in (1..values.len()).rev() {
        let swap_index = rng.below(index + 1);
        values.swap(index, swap_index);
    }

    if values == original && values.len() >= 2 {
        values.swap(0, 1);
    }
}

fn patch_ordinal_table_entry(
    input: &mut PeInput,
    table_rva: u32,
    index: usize,
    value: u16,
) -> bool {
    let offset = match index.checked_mul(2) {
        Some(offset) => offset,
        None => return false,
    };
    let entry_rva = match table_rva.checked_add(offset as u32) {
        Some(entry_rva) => entry_rva,
        None => return false,
    };
    let Some(section) = find_section_containing_rva_mut(&mut input.sections, entry_rva) else {
        return false;
    };
    let relative = match entry_rva.checked_sub(section.virtual_address) {
        Some(relative) => relative,
        None => return false,
    };
    let start = relative as usize;
    let end = match start.checked_add(2) {
        Some(end) => end,
        None => return false,
    };
    if end > section.raw_data.len() {
        return false;
    }

    write_u16_into(&mut section.raw_data, start, value);
    true
}
