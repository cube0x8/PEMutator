use crate::core::io::write_u32_into;
use crate::core::rng::MutRng;
use crate::pe::PeInput;
use crate::pe::data_directories::export::MAX_MUTATION_EXPORT_NAME_POINTERS;
use crate::pe::data_directories::read_name_pointer_entry;
use crate::pe::sections::{find_section_containing_rva_mut, read_string_at_rva};

const MAX_STRING_READ_LEN: usize = 0x400;

pub(super) fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    for _ in 0..8 {
        let mutated = match rng.below(7) {
            0 => duplicate_name_pointer(input, rng),
            1 => swap_name_pointer_entries(input, rng),
            2 => reverse_name_pointer_run(input, rng),
            3 => disorder_name_pointer_sort(input, rng),
            4 => point_name_to_empty_string(input, rng),
            5 => point_name_to_non_ascii_or_unterminated_bytes(input, rng),
            _ => point_name_to_globally_out_of_order_string(input, rng),
        };
        if mutated {
            return true;
        }
    }

    false
}

// Replaces one name pointer entry with a duplicate of another entry.
fn duplicate_name_pointer<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count < 2 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_NAME_POINTERS {
        return false;
    }

    let table_rva = export.name_pointer_rva;
    let source_index = rng.below(count);
    let mut target_index = rng.below(count - 1);
    if target_index >= source_index {
        target_index += 1;
    }

    let Some(source_value) = read_name_pointer_entry(&input.sections, table_rva, source_index)
    else {
        return false;
    };

    patch_name_pointer_entry(input, table_rva, target_index, source_value)
}

// Swaps the RVAs stored in two distinct export name pointer entries.
fn swap_name_pointer_entries<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count < 2 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_NAME_POINTERS {
        return false;
    }

    let table_rva = export.name_pointer_rva;
    let first_index = rng.below(count);
    let mut second_index = rng.below(count - 1);
    if second_index >= first_index {
        second_index += 1;
    }

    let Some(first_value) = read_name_pointer_entry(&input.sections, table_rva, first_index) else {
        return false;
    };
    let Some(second_value) = read_name_pointer_entry(&input.sections, table_rva, second_index)
    else {
        return false;
    };

    patch_name_pointer_entry(input, table_rva, first_index, second_value)
        && patch_name_pointer_entry(input, table_rva, second_index, first_value)
}

// Reverses a contiguous run of export name pointer entries.
fn reverse_name_pointer_run<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count < 2 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_NAME_POINTERS {
        return false;
    }

    let table_rva = export.name_pointer_rva;
    let start = rng.below(count - 1);
    let len = 2 + rng.below(count - start - 1);
    let mut values = Vec::with_capacity(len);
    for index in start..start + len {
        let Some(value) = read_name_pointer_entry(&input.sections, table_rva, index) else {
            return false;
        };
        values.push(value);
    }
    values.reverse();

    for (offset, value) in values.into_iter().enumerate() {
        if !patch_name_pointer_entry(input, table_rva, start + offset, value) {
            return false;
        }
    }

    true
}

// Breaks lexicographic ordering by swapping an in-order adjacent name pair.
fn disorder_name_pointer_sort<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count < 2 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_NAME_POINTERS {
        return false;
    }

    let table_rva = export.name_pointer_rva;
    let mut candidate_pairs = Vec::new();
    for index in 0..count - 1 {
        let Some(left_rva) = read_name_pointer_entry(&input.sections, table_rva, index) else {
            continue;
        };
        let Some(right_rva) = read_name_pointer_entry(&input.sections, table_rva, index + 1) else {
            continue;
        };
        let Some((left_name, _)) =
            read_string_at_rva(&input.sections, left_rva, MAX_STRING_READ_LEN)
        else {
            continue;
        };
        let Some((right_name, _)) =
            read_string_at_rva(&input.sections, right_rva, MAX_STRING_READ_LEN)
        else {
            continue;
        };
        if left_name <= right_name {
            candidate_pairs.push((index, left_rva, right_rva));
        }
    }

    let (index, left_rva, right_rva) = if !candidate_pairs.is_empty() {
        candidate_pairs[rng.below(candidate_pairs.len())]
    } else {
        let index = rng.below(count - 1);
        let Some(left_rva) = read_name_pointer_entry(&input.sections, table_rva, index) else {
            return false;
        };
        let Some(right_rva) = read_name_pointer_entry(&input.sections, table_rva, index + 1) else {
            return false;
        };
        (index, left_rva, right_rva)
    };

    patch_name_pointer_entry(input, table_rva, index, right_rva)
        && patch_name_pointer_entry(input, table_rva, index + 1, left_rva)
}

// Redirects one exported name to an empty string.
fn point_name_to_empty_string<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count == 0 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_NAME_POINTERS {
        return false;
    }

    let table_rva = export.name_pointer_rva;
    let index = rng.below(count);
    let Some(name_rva) = read_name_pointer_entry(&input.sections, table_rva, index) else {
        return false;
    };

    patch_byte_at_rva(input, name_rva, 0)
}

// Corrupts one exported name with a random non-ASCII byte or by removing its terminator.
fn point_name_to_non_ascii_or_unterminated_bytes<R: MutRng>(
    input: &mut PeInput,
    rng: &mut R,
) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count == 0 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_NAME_POINTERS {
        return false;
    }

    let table_rva = export.name_pointer_rva;
    let index = rng.below(count);
    let Some(name_rva) = read_name_pointer_entry(&input.sections, table_rva, index) else {
        return false;
    };

    if rng.coinflip(0.5) {
        let non_ascii = (0x80 + rng.below(0x80)) as u8;
        patch_byte_at_rva(input, name_rva, non_ascii)
    } else {
        patch_string_terminator(input, name_rva, b'X')
    }
}

// Forces one exported name to sort before earlier names by overwriting its first byte.
fn point_name_to_globally_out_of_order_string<R: MutRng>(input: &mut PeInput, rng: &mut R) -> bool {
    let Some(export) = input.export_directory.as_ref() else {
        return false;
    };
    let count = export.number_of_name_pointers as usize;
    if count == 0 || export.number_of_name_pointers > MAX_MUTATION_EXPORT_NAME_POINTERS {
        return false;
    }

    let table_rva = export.name_pointer_rva;
    let index = if count == 1 {
        0
    } else {
        1 + rng.below(count - 1)
    };
    let Some(name_rva) = read_name_pointer_entry(&input.sections, table_rva, index) else {
        return false;
    };

    patch_byte_at_rva(input, name_rva, b'!')
}

fn patch_name_pointer_entry(
    input: &mut PeInput,
    table_rva: u32,
    index: usize,
    new_rva: u32,
) -> bool {
    let Some(offset) = index.checked_mul(4) else {
        return false;
    };
    let Some(entry_rva) = table_rva.checked_add(offset as u32) else {
        return false;
    };

    let Some(section) = find_section_containing_rva_mut(&mut input.sections, entry_rva) else {
        return false;
    };

    let Some(relative) = entry_rva.checked_sub(section.virtual_address) else {
        return false;
    };
    let start = relative as usize;
    let Some(end) = start.checked_add(4) else {
        return false;
    };
    if end > section.raw_data.len() {
        return false;
    }

    write_u32_into(&mut section.raw_data, start, new_rva);
    true
}

fn patch_byte_at_rva(input: &mut PeInput, rva: u32, value: u8) -> bool {
    let Some(section) = find_section_containing_rva_mut(&mut input.sections, rva) else {
        return false;
    };

    let Some(relative) = rva.checked_sub(section.virtual_address) else {
        return false;
    };

    let Some(byte) = section.raw_data.get_mut(relative as usize) else {
        return false;
    };
    *byte = value;

    true
}

fn patch_string_terminator(input: &mut PeInput, rva: u32, replacement: u8) -> bool {
    let Some(section) = find_section_containing_rva_mut(&mut input.sections, rva) else {
        return false;
    };

    let Some(relative) = rva.checked_sub(section.virtual_address) else {
        return false;
    };

    let Some(bytes) = section.raw_data.get_mut(relative as usize..) else {
        return false;
    };

    let Some(nul) = bytes.iter().position(|byte| *byte == 0) else {
        return false;
    };

    bytes[nul] = replacement;
    true
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::core::SimpleRng;
    use crate::core::io::read_c_string_bytes;
    use crate::mutations::directories::export::names::{
        disorder_name_pointer_sort, duplicate_name_pointer, point_name_to_empty_string,
        point_name_to_globally_out_of_order_string, point_name_to_non_ascii_or_unterminated_bytes,
        reverse_name_pointer_run, swap_name_pointer_entries,
    };
    use crate::pe::PeInput;
    use crate::pe::sections::read_string_at_rva;

    use super::MAX_STRING_READ_LEN;

    mod test_util {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/common/mod.rs"));
    }

    #[test]
    fn duplicate_name_pointer_can_duplicate_entries_on_netsh() {
        let bytes = fs::read(test_util::sample_path("netsh.exe")).unwrap();
        let original = PeInput::parse(&bytes).unwrap();
        let export = original
            .export_directory
            .as_ref()
            .expect("netsh.exe should expose a parsed export directory");

        assert_eq!(
            export.number_of_name_pointers, 0x17,
            "test fixture assumption changed: netsh.exe should expose 0x17 name pointers"
        );

        let original_entries = read_name_pointer_entries(&original)
            .expect("expected readable netsh name pointer table");
        assert_eq!(original_entries.len(), 0x17);
        assert!(
            !has_duplicate_entries(&original_entries),
            "netsh.exe fixture unexpectedly already contains duplicate name pointers"
        );

        let mut successful_mutation = None;

        for seed in 1_u64..8192 {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            if !duplicate_name_pointer(&mut candidate, &mut rng) {
                continue;
            }

            let reparsed = PeInput::parse(&candidate.to_bytes().unwrap()).unwrap();
            let Some(entries) = read_name_pointer_entries(&reparsed) else {
                continue;
            };
            if entries.len() != 0x17 {
                continue;
            }
            if has_duplicate_entries(&entries) {
                successful_mutation = Some((seed, entries));
                break;
            }
        }

        let (seed, duplicated_entries) = successful_mutation
            .expect("expected at least one seed to duplicate export name pointers on netsh.exe");
        assert!(
            has_duplicate_entries(&duplicated_entries),
            "seed {seed} should create duplicate name pointer entries on netsh.exe"
        );
    }

    #[test]
    fn swap_name_pointer_entries_can_swap_two_entries_on_netsh() {
        let bytes = fs::read(test_util::sample_path("netsh.exe")).unwrap();
        let original = PeInput::parse(&bytes).unwrap();
        let export = original
            .export_directory
            .as_ref()
            .expect("netsh.exe should expose a parsed export directory");

        assert_eq!(
            export.number_of_name_pointers, 0x17,
            "test fixture assumption changed: netsh.exe should expose 0x17 name pointers"
        );

        let original_entries = read_name_pointer_entries(&original)
            .expect("expected readable netsh name pointer table");
        assert_eq!(original_entries.len(), 0x17);
        assert!(
            !has_duplicate_entries(&original_entries),
            "netsh.exe fixture unexpectedly already contains duplicate name pointers"
        );

        let mut successful_mutation = None;

        for seed in 1_u64..8192 {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            if !swap_name_pointer_entries(&mut candidate, &mut rng) {
                continue;
            }

            let reparsed = PeInput::parse(&candidate.to_bytes().unwrap()).unwrap();
            let Some(entries) = read_name_pointer_entries(&reparsed) else {
                continue;
            };
            if entries.len() != original_entries.len() {
                continue;
            }

            let Some((left, right)) = find_swapped_pair(&original_entries, &entries) else {
                continue;
            };

            successful_mutation = Some((seed, entries, left, right));
            break;
        }

        let (seed, swapped_entries, left, right) = successful_mutation.expect(
            "expected at least one seed to swap two export name pointer entries on netsh.exe",
        );

        assert_eq!(
            swapped_entries[left], original_entries[right],
            "seed {seed} should move the right entry into the left position"
        );
        assert_eq!(
            swapped_entries[right], original_entries[left],
            "seed {seed} should move the left entry into the right position"
        );
    }

    #[test]
    fn reverse_name_pointer_run_can_reverse_a_contiguous_run_on_netsh() {
        let bytes = fs::read(test_util::sample_path("netsh.exe")).unwrap();
        let original = PeInput::parse(&bytes).unwrap();
        let export = original
            .export_directory
            .as_ref()
            .expect("netsh.exe should expose a parsed export directory");

        assert_eq!(
            export.number_of_name_pointers, 0x17,
            "test fixture assumption changed: netsh.exe should expose 0x17 name pointers"
        );

        let original_entries = read_name_pointer_entries(&original)
            .expect("expected readable netsh name pointer table");
        assert_eq!(original_entries.len(), 0x17);

        let mut successful_mutation = None;

        for seed in 1_u64..8192 {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            if !reverse_name_pointer_run(&mut candidate, &mut rng) {
                continue;
            }

            let reparsed = PeInput::parse(&candidate.to_bytes().unwrap()).unwrap();
            let Some(entries) = read_name_pointer_entries(&reparsed) else {
                continue;
            };
            if entries.len() != original_entries.len() {
                continue;
            }

            let Some((start, end)) = find_reversed_run(&original_entries, &entries) else {
                continue;
            };

            successful_mutation = Some((seed, entries, start, end));
            break;
        }

        let (seed, reversed_entries, start, end) = successful_mutation.expect(
            "expected at least one seed to reverse a run of export name pointers on netsh.exe",
        );

        let expected: Vec<_> = original_entries[start..end].iter().rev().copied().collect();
        assert_eq!(
            &reversed_entries[start..end],
            expected.as_slice(),
            "seed {seed} should reverse the contiguous run {start}..{end}"
        );
    }

    #[test]
    fn disorder_name_pointer_sort_can_break_adjacent_name_order_on_netsh() {
        let bytes = fs::read(test_util::sample_path("netsh.exe")).unwrap();
        let original = PeInput::parse(&bytes).unwrap();
        let export = original
            .export_directory
            .as_ref()
            .expect("netsh.exe should expose a parsed export directory");

        assert_eq!(
            export.number_of_name_pointers, 0x17,
            "test fixture assumption changed: netsh.exe should expose 0x17 name pointers"
        );

        let original_entries = read_name_pointer_entries(&original)
            .expect("expected readable netsh name pointer table");
        assert_eq!(original_entries.len(), 0x17);
        assert!(
            find_first_out_of_order_adjacent_pair(&original, &original_entries).is_none(),
            "netsh.exe fixture unexpectedly already contains out-of-order export names"
        );

        let mut successful_mutation = None;

        for seed in 1_u64..8192 {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            if !disorder_name_pointer_sort(&mut candidate, &mut rng) {
                continue;
            }

            let reparsed = PeInput::parse(&candidate.to_bytes().unwrap()).unwrap();
            let Some(entries) = read_name_pointer_entries(&reparsed) else {
                continue;
            };
            if entries.len() != original_entries.len() {
                continue;
            }

            let Some((index, left_name, right_name)) =
                find_first_out_of_order_adjacent_pair(&reparsed, &entries)
            else {
                continue;
            };

            successful_mutation = Some((seed, index, left_name, right_name));
            break;
        }

        let (seed, index, left_name, right_name) = successful_mutation.expect(
            "expected at least one seed to break adjacent export name ordering on netsh.exe",
        );

        assert!(
            left_name > right_name,
            "seed {seed} should make adjacent names out of order at pair {index}: {left_name:?} <= {right_name:?}"
        );
    }

    #[test]
    fn point_name_to_empty_string_can_zero_an_export_name_on_netsh() {
        let bytes = fs::read(test_util::sample_path("netsh.exe")).unwrap();
        let original = PeInput::parse(&bytes).unwrap();
        let export = original
            .export_directory
            .as_ref()
            .expect("netsh.exe should expose a parsed export directory");

        assert_eq!(
            export.number_of_name_pointers, 0x17,
            "test fixture assumption changed: netsh.exe should expose 0x17 name pointers"
        );

        let original_entries = read_name_pointer_entries(&original)
            .expect("expected readable netsh name pointer table");
        assert_eq!(original_entries.len(), 0x17);
        assert!(
            find_first_empty_name_index(&original, &original_entries).is_none(),
            "netsh.exe fixture unexpectedly already contains an empty export name"
        );

        let mut successful_mutation = None;

        for seed in 1_u64..8192 {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            if !point_name_to_empty_string(&mut candidate, &mut rng) {
                continue;
            }

            let reparsed = PeInput::parse(&candidate.to_bytes().unwrap()).unwrap();
            let Some(entries) = read_name_pointer_entries(&reparsed) else {
                continue;
            };
            if entries.len() != original_entries.len() {
                continue;
            }

            let Some(index) = find_first_empty_name_index(&reparsed, &entries) else {
                continue;
            };

            successful_mutation = Some((seed, reparsed, entries, index));
            break;
        }

        let (seed, reparsed, entries, index) = successful_mutation.expect(
            "expected at least one seed to turn an export name into an empty string on netsh.exe",
        );
        let (name, _) = read_string_at_rva(&reparsed.sections, entries[index], MAX_STRING_READ_LEN)
            .expect("mutated export name should remain readable");

        assert!(
            name.is_empty(),
            "seed {seed} should produce an empty export name at index {index}, found {name:?}"
        );
    }

    #[test]
    fn point_name_to_non_ascii_or_unterminated_bytes_can_corrupt_an_export_name_on_netsh() {
        let bytes = fs::read(test_util::sample_path("netsh.exe")).unwrap();
        let original = PeInput::parse(&bytes).unwrap();
        let export = original
            .export_directory
            .as_ref()
            .expect("netsh.exe should expose a parsed export directory");

        assert_eq!(
            export.number_of_name_pointers, 0x17,
            "test fixture assumption changed: netsh.exe should expose 0x17 name pointers"
        );

        let original_entries = read_name_pointer_entries(&original)
            .expect("expected readable netsh name pointer table");
        assert_eq!(original_entries.len(), 0x17);
        assert!(
            find_first_non_ascii_or_unterminated_name(&original, &original_entries).is_none(),
            "netsh.exe fixture unexpectedly already contains a non-ASCII or unterminated export name"
        );

        let mut successful_mutation = None;

        for seed in 1_u64..8192 {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            if !point_name_to_non_ascii_or_unterminated_bytes(&mut candidate, &mut rng) {
                continue;
            }

            let reparsed = PeInput::parse(&candidate.to_bytes().unwrap()).unwrap();
            let Some(entries) = read_name_pointer_entries(&reparsed) else {
                continue;
            };
            if entries.len() != original_entries.len() {
                continue;
            }

            let Some((index, name, terminated)) =
                find_first_non_ascii_or_unterminated_name(&reparsed, &entries)
            else {
                continue;
            };

            successful_mutation = Some((seed, index, name, terminated));
            break;
        }

        let (seed, index, name, terminated) = successful_mutation.expect(
            "expected at least one seed to make an export name non-ASCII or unterminated on netsh.exe",
        );

        assert!(
            !terminated || !name.is_ascii(),
            "seed {seed} should produce a non-ASCII or unterminated export name at index {index}, found {name:?} (terminated={terminated})"
        );
    }

    #[test]
    fn point_name_to_globally_out_of_order_string_can_force_a_name_before_earlier_ones_on_netsh() {
        let bytes = fs::read(test_util::sample_path("netsh.exe")).unwrap();
        let original = PeInput::parse(&bytes).unwrap();
        let export = original
            .export_directory
            .as_ref()
            .expect("netsh.exe should expose a parsed export directory");

        assert_eq!(
            export.number_of_name_pointers, 0x17,
            "test fixture assumption changed: netsh.exe should expose 0x17 name pointers"
        );

        let original_entries = read_name_pointer_entries(&original)
            .expect("expected readable netsh name pointer table");
        assert_eq!(original_entries.len(), 0x17);
        assert!(
            find_first_bang_prefixed_name_index(&original, &original_entries).is_none(),
            "netsh.exe fixture unexpectedly already contains a bang-prefixed export name"
        );

        let mut successful_mutation = None;

        for seed in 1_u64..8192 {
            let mut candidate = original.clone();
            let mut rng = SimpleRng::new(seed);
            if !point_name_to_globally_out_of_order_string(&mut candidate, &mut rng) {
                continue;
            }

            let reparsed = PeInput::parse(&candidate.to_bytes().unwrap()).unwrap();
            let Some(entries) = read_name_pointer_entries(&reparsed) else {
                continue;
            };
            if entries.len() != original_entries.len() {
                continue;
            }

            let Some(index) = find_first_bang_prefixed_name_index(&reparsed, &entries) else {
                continue;
            };
            if index == 0 {
                continue;
            }

            let (previous_name, _) =
                read_string_at_rva(&reparsed.sections, entries[index - 1], MAX_STRING_READ_LEN)
                    .expect("previous export name should remain readable");
            let (name, _) =
                read_string_at_rva(&reparsed.sections, entries[index], MAX_STRING_READ_LEN)
                    .expect("mutated export name should remain readable");
            if name < previous_name {
                successful_mutation = Some((seed, index, previous_name, name));
                break;
            }
        }

        let (seed, index, previous_name, name) = successful_mutation.expect(
            "expected at least one seed to force an export name out of global order on netsh.exe",
        );

        assert!(
            name.starts_with('!'),
            "seed {seed} should create a bang-prefixed name at index {index}, found {name:?}"
        );
        assert!(
            name < previous_name,
            "seed {seed} should make the bang-prefixed name sort before the previous one at index {index}: {name:?} >= {previous_name:?}"
        );
    }

    fn read_name_pointer_entries(input: &PeInput) -> Option<Vec<u32>> {
        let export = input.export_directory.as_ref()?;
        let count = export.number_of_name_pointers as usize;
        let mut entries = Vec::with_capacity(count);

        for index in 0..count {
            let entry_rva = export.name_pointer_rva.checked_add((index * 4) as u32)?;
            let value = input.sections.iter().find_map(|section| {
                let relative = entry_rva.checked_sub(section.virtual_address)?;
                let start = relative as usize;
                let end = start.checked_add(4)?;
                let bytes = section.raw_data.get(start..end)?;
                Some(u32::from_le_bytes(bytes.try_into().unwrap()))
            })?;
            entries.push(value);
        }

        Some(entries)
    }

    fn has_duplicate_entries(entries: &[u32]) -> bool {
        for (index, entry) in entries.iter().enumerate() {
            if entries[index + 1..].contains(entry) {
                return true;
            }
        }
        false
    }

    fn find_swapped_pair(original: &[u32], mutated: &[u32]) -> Option<(usize, usize)> {
        if original.len() != mutated.len() {
            return None;
        }

        let differing_indices: Vec<_> = original
            .iter()
            .zip(mutated.iter())
            .enumerate()
            .filter_map(|(index, (left, right))| (left != right).then_some(index))
            .collect();

        if differing_indices.len() != 2 {
            return None;
        }

        let left = differing_indices[0];
        let right = differing_indices[1];
        if original[left] == mutated[right] && original[right] == mutated[left] {
            Some((left, right))
        } else {
            None
        }
    }

    fn find_reversed_run(original: &[u32], mutated: &[u32]) -> Option<(usize, usize)> {
        if original.len() != mutated.len() {
            return None;
        }

        let start = original
            .iter()
            .zip(mutated.iter())
            .position(|(left, right)| left != right)?;
        let end = original
            .iter()
            .zip(mutated.iter())
            .rposition(|(left, right)| left != right)?
            + 1;

        if end - start < 2 {
            return None;
        }

        if original[..start] != mutated[..start] || original[end..] != mutated[end..] {
            return None;
        }

        let expected: Vec<_> = original[start..end].iter().rev().copied().collect();
        if mutated[start..end] == expected {
            Some((start, end))
        } else {
            None
        }
    }

    fn find_first_out_of_order_adjacent_pair(
        input: &PeInput,
        entries: &[u32],
    ) -> Option<(usize, String, String)> {
        for index in 0..entries.len().saturating_sub(1) {
            let (left_name, _) =
                read_string_at_rva(&input.sections, entries[index], MAX_STRING_READ_LEN)?;
            let (right_name, _) =
                read_string_at_rva(&input.sections, entries[index + 1], MAX_STRING_READ_LEN)?;
            if left_name > right_name {
                return Some((index, left_name, right_name));
            }
        }

        None
    }

    fn find_first_empty_name_index(input: &PeInput, entries: &[u32]) -> Option<usize> {
        for (index, entry_rva) in entries.iter().copied().enumerate() {
            let (name, _) = read_string_at_rva(&input.sections, entry_rva, MAX_STRING_READ_LEN)?;
            if name.is_empty() {
                return Some(index);
            }
        }

        None
    }

    fn find_first_non_ascii_or_unterminated_name(
        input: &PeInput,
        entries: &[u32],
    ) -> Option<(usize, String, bool)> {
        for (index, entry_rva) in entries.iter().copied().enumerate() {
            let (name, terminated) =
                read_string_at_rva(&input.sections, entry_rva, MAX_STRING_READ_LEN)?;
            if !terminated || !name.is_ascii() {
                return Some((index, name, terminated));
            }
        }

        None
    }

    fn find_first_bang_prefixed_name_index(input: &PeInput, entries: &[u32]) -> Option<usize> {
        for (index, entry_rva) in entries.iter().copied().enumerate() {
            let section = input.sections.iter().find(|section| {
                let start = section.virtual_address;
                let end = start.saturating_add(section.raw_data.len() as u32);
                entry_rva >= start && entry_rva < end
            })?;
            let offset = entry_rva.checked_sub(section.virtual_address)? as usize;
            let raw = read_c_string_bytes(&section.raw_data, offset, MAX_STRING_READ_LEN)?;
            if raw.bytes.first().copied() == Some(b'!') {
                return Some(index);
            }
        }

        None
    }
}
