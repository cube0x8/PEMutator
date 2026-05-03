use std::fs;

mod common;

use pe_mutator_core::mutations::ExportDirectoryMutations;
use pe_mutator_core::pe::{PeDataDirectory, PeInput};
use pe_mutator_core::{RawMutationResult, SimpleRng};

#[test]
fn pecompact_psexec_matches_all_optional_header_data_directories() {
    let bytes = fs::read(common::sample_path("pecompact_PsExec.exe")).unwrap();
    let input = PeInput::parse(&bytes).unwrap();

    let expected = vec![
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0007_d624,
            size: 0x0000_008f,
        },
        PeDataDirectory {
            virtual_address: 0x0007_d000,
            size: 0x0000_05fd,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0007_f000,
            size: 0x0000_0018,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0002_759c,
            size: 0x0000_0060,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
    ];

    assert_eq!(input.data_directories.len(), expected.len());
    assert_eq!(input.data_directories, expected);
}

#[test]
fn smartdefrag_boot_time_matches_all_optional_header_data_directories() {
    let bytes = fs::read(common::sample_path("SmartDefragBootTime.exe")).unwrap();
    let input = PeInput::parse(&bytes).unwrap();

    let expected = vec![
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_6af4,
            size: 0x0000_0028,
        },
        PeDataDirectory {
            virtual_address: 0x0000_9000,
            size: 0x0000_0360,
        },
        PeDataDirectory {
            virtual_address: 0x0000_8000,
            size: 0x0000_01c8,
        },
        PeDataDirectory {
            virtual_address: 0x0000_6e00,
            size: 0x0000_4460,
        },
        PeDataDirectory {
            virtual_address: 0x0000_a000,
            size: 0x0000_000c,
        },
        PeDataDirectory {
            virtual_address: 0x0000_1160,
            size: 0x0000_001c,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_1000,
            size: 0x0000_0158,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
        PeDataDirectory {
            virtual_address: 0x0000_0000,
            size: 0x0000_0000,
        },
    ];

    assert_eq!(input.data_directories.len(), expected.len());
    assert_eq!(input.data_directories, expected);
}

#[test]
fn export_random_mutation_stacks_still_reparse_on_netsh() {
    let bytes = fs::read(common::sample_path("netsh.exe")).unwrap();
    let original = PeInput::parse(&bytes).unwrap();
    let mut saw_successful_mutation = false;

    for target_mutations in (7..=70).step_by(7) {
        let mut candidate = original.clone();
        let mut rng = SimpleRng::new(target_mutations as u64);
        let mut successful_mutations = 0_usize;
        let mut attempts = 0_usize;
        let max_attempts = target_mutations * 32;

        while successful_mutations < target_mutations && attempts < max_attempts {
            attempts += 1;
            if ExportDirectoryMutations::random_mutation(&mut candidate, &mut rng)
                == RawMutationResult::Mutated
            {
                successful_mutations += 1;
                saw_successful_mutation = true;

                let mutated_bytes = candidate.to_bytes().unwrap();
                let reparsed = PeInput::parse(&mutated_bytes);
                assert!(
                    reparsed.is_ok(),
                    "failed to reparse netsh.exe after {successful_mutations} successful export mutations"
                );
            }
        }
    }

    assert!(
        saw_successful_mutation,
        "expected at least one export mutation to apply successfully on netsh.exe"
    );
}
