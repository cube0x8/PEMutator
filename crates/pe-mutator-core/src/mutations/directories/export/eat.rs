use crate::MutRng;
use crate::io::write_u32_into;
use crate::mutations::rva::{
    random_rva_in_section, rva_near_section_end, rva_outside_all_sections,
};
use crate::mutations::shared::is_executable_section;
use crate::pe::PeInput;
use crate::pe::data_directories::export::MAX_MUTATION_EXPORT_ADDRESS_TABLE_ENTRIES;
use crate::pe::data_directories::read_export_address_table_entry;
use crate::pe::sections::{
    DATA_SECTION_NAMES, PeSection, find_section_containing_rva_mut, pick_random_section,
};

pub(super) fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    match rng.below(4) {
        0 => mutate_eat_base_cases(input, rng),
        1 => mutate_single_corrupt_eat_entry(input, rng),
        2 => mutate_all_eat_entries_equal(input, rng),
        _ => mutate_mix_valid_and_invalid_eat_entries(input, rng),
    }
}

// Mutates one EAT DWORD using the base cases.
fn mutate_eat_base_cases<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.address_table_entries as usize;
    if count == 0 || export.address_table_entries > MAX_MUTATION_EXPORT_ADDRESS_TABLE_ENTRIES {
        return false;
    }

    let table_rva = export.export_address_table_rva;
    let index = rng.below(count);
    if read_export_address_table_entry(&input.sections, table_rva, index).is_none() {
        return false;
    }

    let Some(new_value) = pick_base_eat_value(&input.sections, table_rva, count, index, rng) else {
        return false;
    };

    patch_export_address_table_entry(input, table_rva, index, new_value)
}

// Corrupts exactly one EAT entry with a clearly suspicious target RVA.
fn mutate_single_corrupt_eat_entry<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.address_table_entries as usize;
    if count == 0 || export.address_table_entries > MAX_MUTATION_EXPORT_ADDRESS_TABLE_ENTRIES {
        return false;
    }

    let table_rva = export.export_address_table_rva;
    let index = rng.below(count);
    if read_export_address_table_entry(&input.sections, table_rva, index).is_none() {
        return false;
    }

    let new_value = pick_invalid_eat_value(&input.sections, rng);
    patch_export_address_table_entry(input, table_rva, index, new_value)
}

// Replaces every EAT DWORD with the same value.
fn mutate_all_eat_entries_equal<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.address_table_entries as usize;
    if count == 0 || export.address_table_entries > MAX_MUTATION_EXPORT_ADDRESS_TABLE_ENTRIES {
        return false;
    }

    let table_rva = export.export_address_table_rva;
    let target_index = rng.below(count);
    let Some(new_value) = pick_base_eat_value(&input.sections, table_rva, count, target_index, rng)
    else {
        return false;
    };

    let mut mutated = false;
    for index in 0..count {
        if !patch_export_address_table_entry(input, table_rva, index, new_value) {
            return mutated;
        }
        mutated = true;
    }

    mutated
}

// Writes a table-wide blend of plausible and invalid EAT RVAs.
fn mutate_mix_valid_and_invalid_eat_entries<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.address_table_entries as usize;
    if count < 2 || export.address_table_entries > MAX_MUTATION_EXPORT_ADDRESS_TABLE_ENTRIES {
        return false;
    }

    let table_rva = export.export_address_table_rva;
    let mut saw_valid = false;
    let mut saw_invalid = false;
    let mut mutated = false;

    for index in 0..count {
        let value = if rng.coinflip(0.5) {
            saw_valid = true;
            pick_valid_eat_value(&input.sections, rng)
        } else {
            saw_invalid = true;
            pick_invalid_eat_value(&input.sections, rng)
        };

        if !patch_export_address_table_entry(input, table_rva, index, value) {
            return mutated;
        }
        mutated = true;
    }

    if !mutated {
        return false;
    }
    if saw_valid && saw_invalid {
        return true;
    }

    let forced_index = rng.below(count);
    let forced_value = if saw_valid {
        pick_invalid_eat_value(&input.sections, rng)
    } else {
        pick_valid_eat_value(&input.sections, rng)
    };
    patch_export_address_table_entry(input, table_rva, forced_index, forced_value)
}

fn pick_base_eat_value<R: MutRng>(
    sections: &[PeSection],
    table_rva: u32,
    count: usize,
    target_index: usize,
    rng: &mut R,
) -> Option<u32> {
    match rng.below(6) {
        0 => Some(0),
        1 => Some(pick_plausible_text_rva(sections, rng)),
        2 => Some(pick_plausible_rdata_rva(sections, rng)),
        3 => Some(rva_outside_all_sections(sections, rng)),
        4 => Some(pick_rva_near_section_end(sections, rng)),
        _ => pick_duplicate_eat_entry(sections, table_rva, count, target_index, rng),
    }
}

fn pick_valid_eat_value<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    match rng.below(2) {
        0 => pick_plausible_text_rva(sections, rng),
        _ => pick_plausible_rdata_rva(sections, rng),
    }
}

fn pick_invalid_eat_value<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    match rng.below(3) {
        0 => 0,
        1 => rva_outside_all_sections(sections, rng),
        _ => pick_rva_near_section_end(sections, rng),
    }
}

fn pick_plausible_text_rva<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    sections
        .iter()
        .filter(|section| is_executable_section(section))
        .collect::<Vec<_>>()
        .get(
            rng.below(
                sections
                    .iter()
                    .filter(|section| is_executable_section(section))
                    .count()
                    .max(1),
            ),
        )
        .map(|section| random_rva_in_section(section, rng))
        .unwrap_or_else(|| {
            pick_random_section(sections, rng)
                .map(|section| random_rva_in_section(section, rng))
                .unwrap_or(0)
        })
}

fn pick_plausible_rdata_rva<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    let matching: Vec<_> = sections
        .iter()
        .filter(|section| {
            let name = section.name_string();
            name == ".rdata"
                || DATA_SECTION_NAMES
                    .iter()
                    .any(|candidate| *candidate == name.as_bytes())
        })
        .collect();

    if !matching.is_empty() {
        return random_rva_in_section(matching[rng.below(matching.len())], rng);
    }

    pick_random_section(sections, rng)
        .map(|section| random_rva_in_section(section, rng))
        .unwrap_or(0)
}

fn pick_rva_near_section_end<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    pick_random_section(sections, rng)
        .map(|section| rva_near_section_end(section, rng))
        .unwrap_or_else(|| rva_outside_all_sections(sections, rng))
}

fn pick_duplicate_eat_entry<R: MutRng>(
    sections: &[PeSection],
    table_rva: u32,
    count: usize,
    target_index: usize,
    rng: &mut R,
) -> Option<u32> {
    if count < 2 {
        return None;
    }

    let mut source_index = rng.below(count - 1);
    if source_index >= target_index {
        source_index += 1;
    }
    read_export_address_table_entry(sections, table_rva, source_index)
}

fn patch_export_address_table_entry(
    input: &mut PeInput,
    table_rva: u32,
    index: usize,
    value: u32,
) -> bool {
    let offset = match index.checked_mul(4) {
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
    let end = match start.checked_add(4) {
        Some(end) => end,
        None => return false,
    };
    if end > section.raw_data.len() {
        return false;
    }

    write_u32_into(&mut section.raw_data, start, value);
    true
}
