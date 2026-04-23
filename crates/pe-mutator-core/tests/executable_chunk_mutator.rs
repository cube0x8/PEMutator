use std::fs;

mod common;

use iced_x86::{Decoder, DecoderOptions};
use pe_mutator_core::{
    assembly::{AssemblyBackend, AssemblyBlock},
    core::{
        ExecutableChunkAssemblyMutations, ExecutableChunkMutationPlan, RawMutationResult,
        SimpleRng, plan_executable_chunk_assembly_mutation,
    },
    pe::PeInput,
};

fn instruction_count(block: &AssemblyBlock) -> usize {
    match block {
        AssemblyBlock::X86(block) => block.insns.len(),
        AssemblyBlock::X64(block) => block.insns.len(),
    }
}

fn decode_instruction_count(plan: &ExecutableChunkMutationPlan) -> usize {
    let bitness = match plan.backend {
        AssemblyBackend::X86 => 32,
        AssemblyBackend::X64 => 64,
    };
    let mut decoder = Decoder::with_ip(
        bitness,
        &plan.block_bytes[..plan.encoded_len],
        plan.placement.block_base_va,
        DecoderOptions::NONE,
    );
    let mut count = 0;
    while decoder.can_decode() {
        let _ = decoder.decode();
        count += 1;
    }
    count
}

fn find_valid_plan(input: &PeInput) -> (u64, ExecutableChunkMutationPlan) {
    for seed in 0x4242_u64..0x4342_u64 {
        let mut rng = SimpleRng::new(seed);
        match plan_executable_chunk_assembly_mutation(&mut rng, input) {
            Ok(Some(plan)) => return (seed, plan),
            Ok(None) | Err(_) => continue,
        }
    }

    panic!("expected to find at least one valid executable chunk mutation plan");
}

#[test]
fn executable_chunk_mutator_writes_the_planned_block_at_the_planned_offset() {
    let bytes = fs::read(common::sample_path("SmartDefragBootTime.exe")).unwrap();
    let original = PeInput::parse(&bytes).unwrap();

    let (seed, plan) = find_valid_plan(&original);

    let mut mutated = original.clone();
    let mut rng = SimpleRng::new(seed);
    let result = ExecutableChunkAssemblyMutations::random_mutation(&mut mutated, &mut rng).unwrap();

    assert_eq!(result, RawMutationResult::Mutated);

    let section = &mutated.sections[plan.section_index];
    let chunk_end = plan.chunk_offset + plan.chunk_len;
    assert_eq!(
        &section.raw_data[plan.chunk_offset..chunk_end],
        plan.block_bytes.as_slice(),
        "the mutator should write the planned block bytes at the planned chunk offset"
    );

    assert_eq!(
        decode_instruction_count(&plan),
        instruction_count(&plan.block),
        "the encoded block prefix should decode to the same number of instructions as the planned IR block"
    );
}

#[test]
fn executable_chunk_planning_never_uses_esp_as_x86_index_register() {
    let bytes = fs::read(common::sample_path("SmartDefragBootTime.exe")).unwrap();
    let input = PeInput::parse(&bytes).unwrap();

    for seed in 0_u64..512 {
        let mut rng = SimpleRng::new(seed);
        if let Err(err) = plan_executable_chunk_assembly_mutation(&mut rng, &input) {
            let err_text = format!("{err}");
            assert!(
                !err_text.contains("ESP/RSP can't be used as an index register"),
                "seed {seed} triggered an invalid x86 index register selection: {err_text}"
            );
        }
    }
}

#[test]
fn executable_chunk_planning_never_uses_out_of_range_x64_absolute_addresses() {
    let bytes = fs::read(common::sample_path("SmartDefragBootTime.exe")).unwrap();
    let input = PeInput::parse(&bytes).unwrap();

    for seed in 0_u64..512 {
        let mut rng = SimpleRng::new(seed);
        if let Err(err) = plan_executable_chunk_assembly_mutation(&mut rng, &input) {
            let err_text = format!("{err}");
            assert!(
                !err_text.contains("Displacement must fit in an i32"),
                "seed {seed} triggered an out-of-range x64 absolute address: {err_text}"
            );
        }
    }
}
