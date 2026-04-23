use std::fs;

mod common;

use pe_mutator_core::{
    core::{EntryPointMutations, RawMutationResult, SimpleRng},
    pe::PeInput,
};

#[test]
fn entry_point_mutator_rewrites_entrypoint_on_real_x86_pe() {
    let bytes = fs::read(common::sample_path("SmartDefragBootTime.exe")).unwrap();
    let mut input = PeInput::parse(&bytes).unwrap();
    let original = input.clone();

    let original_entry_section_index = input.entry_section_index();
    let original_entry_bytes = input.entry_bytes().map(|bytes| bytes.to_vec());
    let original_entry_point = input.entry_point();

    let mut rng = SimpleRng::new(0x1337);
    let result = EntryPointMutations::random_mutation(&mut input, &mut rng).unwrap();

    assert_eq!(result, RawMutationResult::Mutated);

    let entry_section_index = input
        .entry_section_index()
        .expect("mutated entry point should map to a section");
    let entry_section = &input.sections[entry_section_index];
    let entry_offset = (input.entry_point() - entry_section.virtual_address) as usize;

    assert!(
        entry_offset < entry_section.raw_data.len(),
        "entry point offset should point inside section raw data"
    );
    if original_entry_section_index.is_some() {
        assert_eq!(
            input.entry_point(),
            original_entry_point,
            "when the original entry point is already mapped, the mutator should rewrite code in place"
        );
    }
    assert_ne!(
        input.to_bytes().unwrap(),
        original.to_bytes().unwrap(),
        "entry point mutation should change the serialized PE"
    );

    let mutated_entry_bytes = input.entry_bytes().map(|bytes| bytes.to_vec());
    assert_ne!(
        mutated_entry_bytes, original_entry_bytes,
        "entry point bytes should differ after mutation"
    );
    assert!(
        input.entry_point() != original_entry_point
            || input.entry_bytes() != original.entry_bytes(),
        "either the entry point RVA or the entry bytes must change"
    );

    let reparsed = PeInput::parse(&input.to_bytes().unwrap()).unwrap();
    assert_eq!(reparsed.entry_point(), input.entry_point());
    assert!(reparsed.entry_section_index().is_some());
}
