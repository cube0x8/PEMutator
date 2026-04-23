use crate::core::io::{write_u16_into, write_u32_into};
use crate::core::rng::MutRng;
use crate::mutations::shared::RawMutationResult;
use crate::pe::data_directories::resource::{
    ParsedResourceDirectory, ParsedResourceEntry, ResourceEntryTarget,
};
use crate::pe::data_directories::resource::directory::{
    IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_RESOURCE_DIRECTORY_LEN,
};
use crate::pe::data_directories::resource::entry::IMAGE_RESOURCE_DIRECTORY_ENTRY_LEN;
use crate::pe::data_directories::parse_resource_directory_tree;
use crate::pe::sections::{PeSection, find_section_containing_rva_mut, section_span};
use crate::pe::PeInput;

const DIRECTORY_ENTRY_COUNT_WEIGHT: usize = 3;
const ENTRY_POINTER_WEIGHT: usize = 3;
const DATA_RVA_WEIGHT: usize = 2;
const RECURSIVE_LOOP_WEIGHT: usize = 2;

const RESOURCE_DIRECTORY_NAMED_COUNT_OFFSET: usize = 12;
const RESOURCE_DIRECTORY_ID_COUNT_OFFSET: usize = 14;
const RESOURCE_ENTRY_POINTER_OFFSET: usize = 4;
const RESOURCE_DATA_ENTRY_DATA_RVA_OFFSET: usize = 0;

#[derive(Clone, Copy)]
struct DirectoryTarget {
    table_offset: u32,
    named_entries: u16,
    id_entries: u16,
}

#[derive(Clone, Copy)]
struct EntryTarget {
    entry_offset: u32,
    table_offset: u32,
    raw_pointer: u32,
}

#[derive(Clone, Copy)]
struct DataEntryTarget {
    data_entry_offset: u32,
}

pub(super) fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
    let Some(parsed_root) = input.resource_directory.as_ref() else {
        return RawMutationResult::Skipped;
    };

    let Some(resource_root_rva) = resource_root_rva(input) else {
        return RawMutationResult::Skipped;
    };

    let mut directories = Vec::new();
    let mut entries = Vec::new();
    let mut data_entries = Vec::new();
    collect_targets(parsed_root, &mut directories, &mut entries, &mut data_entries);

    let bucket = rng.below(
        DIRECTORY_ENTRY_COUNT_WEIGHT
            + ENTRY_POINTER_WEIGHT
            + DATA_RVA_WEIGHT
            + RECURSIVE_LOOP_WEIGHT,
    );

    let mutated = if bucket < DIRECTORY_ENTRY_COUNT_WEIGHT {
        mutate_directory_entry_count(input, resource_root_rva, &directories, rng)
    } else if bucket < DIRECTORY_ENTRY_COUNT_WEIGHT + ENTRY_POINTER_WEIGHT {
        mutate_entry_pointer(input, resource_root_rva, &entries, rng)
    } else if bucket < DIRECTORY_ENTRY_COUNT_WEIGHT + ENTRY_POINTER_WEIGHT + DATA_RVA_WEIGHT {
        mutate_data_rva(input, resource_root_rva, &data_entries, rng)
    } else {
        mutate_recursive_loop(input, resource_root_rva, &directories, &entries, rng)
    };

    if !mutated {
        return RawMutationResult::Skipped;
    }

    input.resource_directory = parse_resource_directory_tree(&input.data_directories, &input.sections);
    RawMutationResult::Mutated
}

fn collect_targets(
    directory: &ParsedResourceDirectory,
    directories: &mut Vec<DirectoryTarget>,
    entries: &mut Vec<EntryTarget>,
    data_entries: &mut Vec<DataEntryTarget>,
) {
    directories.push(DirectoryTarget {
        table_offset: directory.table_offset,
        named_entries: directory.header.number_of_named_entries,
        id_entries: directory.header.number_of_id_entries,
    });

    for entry in &directory.entries {
        entries.push(EntryTarget {
            entry_offset: entry.entry_offset,
            table_offset: directory.table_offset,
            raw_pointer: entry.raw_entry.offset_to_data_or_directory,
        });
        collect_entry_targets(entry, directories, entries, data_entries);
    }
}

fn collect_entry_targets(
    entry: &ParsedResourceEntry,
    directories: &mut Vec<DirectoryTarget>,
    entries: &mut Vec<EntryTarget>,
    data_entries: &mut Vec<DataEntryTarget>,
) {
    match &entry.target {
        ResourceEntryTarget::Directory(child) => {
            collect_targets(child, directories, entries, data_entries);
        }
        ResourceEntryTarget::Data(_) => {
            if let Some(data_entry_offset) = entry.raw_entry.offset_to_data_entry() {
                data_entries.push(DataEntryTarget { data_entry_offset });
            }
        }
    }
}

fn mutate_directory_entry_count<R: MutRng>(
    input: &mut PeInput,
    resource_root_rva: u32,
    directories: &[DirectoryTarget],
    rng: &mut R,
) -> bool {
    let Some(target) = pick_random(directories, rng) else {
        return false;
    };

    let original_total = u32::from(target.named_entries) + u32::from(target.id_entries);
    let new_total = if rng.coinflip(0.5) {
        rng.next_u64() as u16 as u32
    } else {
        pick_special_entry_count(original_total, rng)
    };

    let named = if new_total == 0 {
        0
    } else if target.named_entries > 0 {
        rng.below((new_total as usize).saturating_add(1)) as u16
    } else {
        0
    };
    let id_entries = (new_total.saturating_sub(u32::from(named))).min(u32::from(u16::MAX)) as u16;

    write_resource_u16(
        input,
        resource_root_rva,
        target
            .table_offset
            .saturating_add(RESOURCE_DIRECTORY_NAMED_COUNT_OFFSET as u32),
        named,
    ) && write_resource_u16(
        input,
        resource_root_rva,
        target
            .table_offset
            .saturating_add(RESOURCE_DIRECTORY_ID_COUNT_OFFSET as u32),
        id_entries,
    )
}

fn mutate_entry_pointer<R: MutRng>(
    input: &mut PeInput,
    resource_root_rva: u32,
    entries: &[EntryTarget],
    rng: &mut R,
) -> bool {
    let Some(target) = pick_random(entries, rng) else {
        return false;
    };

    let Some(directory_size) = resource_directory_size(input) else {
        return false;
    };
    let current_is_directory = (target.raw_pointer & 0x8000_0000) != 0;
    let new_pointer = pick_special_entry_pointer(
        current_is_directory,
        target.table_offset,
        target.entry_offset,
        directory_size,
        rng,
    );

    write_resource_u32(
        input,
        resource_root_rva,
        target
            .entry_offset
            .saturating_add(RESOURCE_ENTRY_POINTER_OFFSET as u32),
        new_pointer,
    )
}

fn mutate_data_rva<R: MutRng>(
    input: &mut PeInput,
    resource_root_rva: u32,
    data_entries: &[DataEntryTarget],
    rng: &mut R,
) -> bool {
    let Some(target) = pick_random(data_entries, rng) else {
        return false;
    };

    let new_rva = pick_special_data_rva(&input.sections, rng);
    if !write_resource_u32(
        input,
        resource_root_rva,
        target
            .data_entry_offset
            .saturating_add(RESOURCE_DATA_ENTRY_DATA_RVA_OFFSET as u32),
        new_rva,
    ) {
        return false;
    }

    true
}

fn mutate_recursive_loop<R: MutRng>(
    input: &mut PeInput,
    resource_root_rva: u32,
    directories: &[DirectoryTarget],
    entries: &[EntryTarget],
    rng: &mut R,
) -> bool {
    let loop_candidates: Vec<_> = entries
        .iter()
        .copied()
        .filter(|entry| directories.iter().any(|dir| dir.table_offset < entry.entry_offset))
        .collect();
    let Some(entry) = pick_random(&loop_candidates, rng) else {
        return false;
    };

    let preceding_directories: Vec<_> = directories
        .iter()
        .copied()
        .filter(|dir| dir.table_offset < entry.entry_offset)
        .collect();
    let Some(target_directory) = pick_random(&preceding_directories, rng) else {
        return false;
    };

    let loop_pointer = 0x8000_0000_u32 | target_directory.table_offset;
    write_resource_u32(
        input,
        resource_root_rva,
        entry
            .entry_offset
            .saturating_add(RESOURCE_ENTRY_POINTER_OFFSET as u32),
        loop_pointer,
    )
}

fn pick_special_entry_count<R: MutRng>(current: u32, rng: &mut R) -> u32 {
    match rng.below(10) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => current.wrapping_add(1),
        4 => current.wrapping_sub(1),
        5 => 0xff,
        6 => 0x100,
        7 => 0x7fff,
        8 => 0xffff,
        _ => rng.below(0x1_0000) as u32,
    }
}

fn pick_special_entry_pointer<R: MutRng>(
    current_is_directory: bool,
    table_offset: u32,
    entry_offset: u32,
    directory_size: u32,
    rng: &mut R,
) -> u32 {
    if rng.coinflip(0.3) {
        return rng.next_u64() as u32;
    }

    let raw_offset = match rng.below(9) {
        0 => 0,
        1 => table_offset,
        2 => table_offset.saturating_add(IMAGE_RESOURCE_DIRECTORY_LEN as u32),
        3 => entry_offset,
        4 => entry_offset.saturating_add(IMAGE_RESOURCE_DIRECTORY_ENTRY_LEN as u32),
        5 => directory_size.saturating_sub(1),
        6 => directory_size,
        7 => u32::MAX >> 1,
        _ => rng.next_u64() as u32 & 0x7fff_ffff,
    };

    let make_directory = if rng.coinflip(0.5) {
        current_is_directory
    } else {
        !current_is_directory
    };

    if make_directory {
        0x8000_0000 | (raw_offset & 0x7fff_ffff)
    } else {
        raw_offset & 0x7fff_ffff
    }
}

fn pick_special_data_rva<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    if sections.is_empty() {
        return rng.next_u64() as u32;
    }

    let section = &sections[rng.below(sections.len())];
    let start = section.virtual_address;
    let end = start.saturating_add(section_span(section));
    let max_file_rva = sections
        .iter()
        .map(|section| section.virtual_address.saturating_add(section.raw_data.len() as u32))
        .max()
        .unwrap_or(0);

    match rng.below(8) {
        0 => start,
        1 => end,
        2 => end.saturating_sub(1),
        3 => end.saturating_add(1),
        4 => max_file_rva.saturating_add(1),
        5 => max_file_rva.saturating_add(rng.below(0x1000) as u32),
        6 => u32::MAX,
        _ => rng.next_u64() as u32,
    }
}

fn resource_root_rva(input: &PeInput) -> Option<u32> {
    let directory = input.data_directories.get(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
    (directory.virtual_address != 0).then_some(directory.virtual_address)
}

fn resource_directory_size(input: &PeInput) -> Option<u32> {
    let directory = input.data_directories.get(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
    Some(directory.size)
}

fn write_resource_u16(input: &mut PeInput, resource_root_rva: u32, offset: u32, value: u16) -> bool {
    let absolute_rva = match resource_root_rva.checked_add(offset) {
        Some(rva) => rva,
        None => return false,
    };
    let Some(section) = find_section_containing_rva_mut(&mut input.sections, absolute_rva) else {
        return false;
    };
    let Some(start) = absolute_rva.checked_sub(section.virtual_address) else {
        return false;
    };
    let start = start as usize;
    let end = start.saturating_add(2);
    if end > section.raw_data.len() {
        return false;
    }
    write_u16_into(&mut section.raw_data, start, value);
    true
}

fn write_resource_u32(input: &mut PeInput, resource_root_rva: u32, offset: u32, value: u32) -> bool {
    let absolute_rva = match resource_root_rva.checked_add(offset) {
        Some(rva) => rva,
        None => return false,
    };
    let Some(section) = find_section_containing_rva_mut(&mut input.sections, absolute_rva) else {
        return false;
    };
    let Some(start) = absolute_rva.checked_sub(section.virtual_address) else {
        return false;
    };
    let start = start as usize;
    let end = start.saturating_add(4);
    if end > section.raw_data.len() {
        return false;
    }
    write_u32_into(&mut section.raw_data, start, value);
    true
}

fn pick_random<T: Copy, R: MutRng>(items: &[T], rng: &mut R) -> Option<T> {
    if items.is_empty() {
        None
    } else {
        Some(items[rng.below(items.len())])
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::core::SimpleRng;
    use crate::core::io::{read_u16, read_u32};
    use crate::pe::sections::slice_at_rva;

    use super::*;

    mod test_util {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/common/mod.rs"));
    }

    const RESOURCE_FIXTURES: &[&str] = &[
        "geek.exe",
        "procexp.exe",
        "ComIntRep.exe",
        "HDDScan.exe",
        "mmc.exe",
    ];

    #[test]
    fn mutate_directory_entry_count_changes_a_resource_directory_header_count() {
        let (original, fixture_name, root_rva, directories, _, _) =
            load_fixture_matching(|directories, _, _| !directories.is_empty());
        let before = snapshot_directory_counts(&original, root_rva, &directories);

        let changed = (1_u64..=4096).find_map(|seed| {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            mutate_directory_entry_count(&mut candidate, root_rva, &directories, &mut rng)
                .then(|| snapshot_directory_counts(&candidate, root_rva, &directories))
                .filter(|after| *after != before)
        });

        assert!(
            changed.is_some(),
            "expected directory entry-count mutation to change a resource directory header in {fixture_name}"
        );
    }

    #[test]
    fn mutate_entry_pointer_changes_a_resource_directory_entry_pointer() {
        let (original, fixture_name, root_rva, _, entries, _) =
            load_fixture_matching(|_, entries, _| !entries.is_empty());
        let before = snapshot_entry_pointers(&original, root_rva, &entries);

        let changed = (1_u64..=4096).find_map(|seed| {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            mutate_entry_pointer(&mut candidate, root_rva, &entries, &mut rng)
                .then(|| snapshot_entry_pointers(&candidate, root_rva, &entries))
                .filter(|after| *after != before)
        });

        assert!(
            changed.is_some(),
            "expected entry-pointer mutation to change a resource directory entry pointer in {fixture_name}"
        );
    }

    #[test]
    fn mutate_data_rva_changes_a_resource_data_entry_rva() {
        let (original, fixture_name, root_rva, _, _, data_entries) =
            load_fixture_matching(|_, _, data_entries| !data_entries.is_empty());
        let before = snapshot_data_rvas(&original, root_rva, &data_entries);

        let changed = (1_u64..=4096).find_map(|seed| {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            mutate_data_rva(&mut candidate, root_rva, &data_entries, &mut rng)
                .then(|| snapshot_data_rvas(&candidate, root_rva, &data_entries))
                .filter(|after| *after != before)
        });

        assert!(
            changed.is_some(),
            "expected data-rva mutation to change a resource data entry RVA in {fixture_name}"
        );
    }

    #[test]
    fn mutate_recursive_loop_points_an_entry_to_a_preceding_directory() {
        let (original, fixture_name, root_rva, directories, entries, _) = load_fixture_matching(
            |directories, entries, _| {
                entries
                    .iter()
                    .any(|entry| directories.iter().any(|dir| dir.table_offset < entry.entry_offset))
            },
        );
        let before = snapshot_entry_pointers(&original, root_rva, &entries);

        let changed = (1_u64..=4096).find_map(|seed| {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            if !mutate_recursive_loop(&mut candidate, root_rva, &directories, &entries, &mut rng) {
                return None;
            }

            let after = snapshot_entry_pointers(&candidate, root_rva, &entries);
            let changed_to_preceding_directory =
                after.iter().enumerate().any(|(index, (_, new_value))| {
                let (_, old_value) = before[index];
                if *new_value == old_value || (new_value & 0x8000_0000) == 0 {
                    return false;
                }

                let target_offset = new_value & 0x7fff_ffff;
                let entry = entries[index];
                directories
                    .iter()
                    .any(|dir| dir.table_offset == target_offset && dir.table_offset < entry.entry_offset)
            });

            changed_to_preceding_directory.then_some(())
        });

        assert!(
            changed.is_some(),
            "expected recursive-loop mutation to point an entry at a preceding directory in {fixture_name}"
        );
    }

    fn load_fixture_matching<F>(
        predicate: F,
    ) -> (
        PeInput,
        &'static str,
        u32,
        Vec<DirectoryTarget>,
        Vec<EntryTarget>,
        Vec<DataEntryTarget>,
    )
    where
        F: Fn(&[DirectoryTarget], &[EntryTarget], &[DataEntryTarget]) -> bool,
    {
        for fixture_name in RESOURCE_FIXTURES {
            let bytes = fs::read(test_util::sample_path(fixture_name)).unwrap();
            let input = PeInput::parse(&bytes).unwrap();
            let Some(parsed_root) = input.resource_directory.clone() else {
                continue;
            };
            let Some(root_rva) = resource_root_rva(&input) else {
                continue;
            };

            let mut directories = Vec::new();
            let mut entries = Vec::new();
            let mut data_entries = Vec::new();
            collect_targets(&parsed_root, &mut directories, &mut entries, &mut data_entries);

            if predicate(&directories, &entries, &data_entries) {
                return (input, fixture_name, root_rva, directories, entries, data_entries);
            }
        }

        panic!("no resource fixture satisfied the requested resource-tree constraints");
    }

    fn snapshot_directory_counts(
        input: &PeInput,
        root_rva: u32,
        directories: &[DirectoryTarget],
    ) -> Vec<(u32, u16, u16)> {
        directories
            .iter()
            .map(|directory| {
                let named = read_resource_u16_for_test(
                    input,
                    root_rva,
                    directory.table_offset + RESOURCE_DIRECTORY_NAMED_COUNT_OFFSET as u32,
                );
                let ids = read_resource_u16_for_test(
                    input,
                    root_rva,
                    directory.table_offset + RESOURCE_DIRECTORY_ID_COUNT_OFFSET as u32,
                );
                (directory.table_offset, named, ids)
            })
            .collect()
    }

    fn snapshot_entry_pointers(
        input: &PeInput,
        root_rva: u32,
        entries: &[EntryTarget],
    ) -> Vec<(u32, u32)> {
        entries
            .iter()
            .map(|entry| {
                let pointer = read_resource_u32_for_test(
                    input,
                    root_rva,
                    entry.entry_offset + RESOURCE_ENTRY_POINTER_OFFSET as u32,
                );
                (entry.entry_offset, pointer)
            })
            .collect()
    }

    fn snapshot_data_rvas(
        input: &PeInput,
        root_rva: u32,
        data_entries: &[DataEntryTarget],
    ) -> Vec<(u32, u32)> {
        data_entries
            .iter()
            .map(|entry| {
                let data_rva = read_resource_u32_for_test(
                    input,
                    root_rva,
                    entry.data_entry_offset + RESOURCE_DATA_ENTRY_DATA_RVA_OFFSET as u32,
                );
                (entry.data_entry_offset, data_rva)
            })
            .collect()
    }

    fn read_resource_u16_for_test(input: &PeInput, root_rva: u32, offset: u32) -> u16 {
        let bytes = slice_at_rva(&input.sections, root_rva + offset, 2)
            .expect("resource bytes should remain readable for the targeted field");
        read_u16(bytes, 0).unwrap()
    }

    fn read_resource_u32_for_test(input: &PeInput, root_rva: u32, offset: u32) -> u32 {
        let bytes = slice_at_rva(&input.sections, root_rva + offset, 4)
            .expect("resource bytes should remain readable for the targeted field");
        read_u32(bytes, 0).unwrap()
    }
}
