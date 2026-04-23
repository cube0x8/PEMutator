use crate::core::rng::MutRng;
use crate::mutations::mutations::InPlaceMutation;
use crate::mutations::shared::RawMutationResult;
use crate::pe::{
    PeInput, SECTION_CHARACTERISTIC_FLAGS, SECTION_CHARACTERISTIC_MUTATION_BITS,
    SECTION_NAME_DICTIONARY,
};

pub struct SectionHeaderMutations;

impl SectionHeaderMutations {
    pub fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
        if input.sections.is_empty() {
            return RawMutationResult::Skipped;
        }

        let index = rng.below(input.sections.len());
        let section = &mut input.sections[index];

        match rng.below(9) {
            0 => {
                let name = SECTION_NAME_DICTIONARY[rng.below(SECTION_NAME_DICTIONARY.len())];
                section.name.fill(0);
                let len = name.len().min(section.name.len());
                section.name[..len].copy_from_slice(&name[..len]);
            }
            1 => {
                section.virtual_size = if rng.coinflip(0.5) {
                    section.size_of_raw_data()
                } else {
                    section
                        .size_of_raw_data()
                        .saturating_add(rng.below(0x400) as u32)
                };
            }
            2 => {
                let bit = SECTION_CHARACTERISTIC_MUTATION_BITS
                    [rng.below(SECTION_CHARACTERISTIC_MUTATION_BITS.len())];
                section.characteristics ^= bit;
            }
            3 => {
                let mut characteristics = 0_u32;
                for flag in SECTION_CHARACTERISTIC_FLAGS {
                    if rng.coinflip(0.25) {
                        characteristics |= flag;
                    }
                }
                if characteristics == 0 {
                    characteristics =
                        SECTION_CHARACTERISTIC_FLAGS[rng.below(SECTION_CHARACTERISTIC_FLAGS.len())];
                }
                section.characteristics = characteristics;
            }
            4 => {
                let delta = rng.below(0x400) as u32;
                section.virtual_size = if rng.coinflip(0.5) {
                    section.virtual_size.saturating_add(delta)
                } else {
                    section.virtual_size.saturating_sub(delta)
                };
            }
            5 => {
                let delta = rng.below(0x400) as u32;
                section.declared_size_of_raw_data = if rng.coinflip(0.5) {
                    section.header_size_of_raw_data().saturating_add(delta)
                } else {
                    section.header_size_of_raw_data().saturating_sub(delta)
                };
            }
            6 => {
                let delta = rng.below(0x1000) as u32;
                section.declared_pointer_to_raw_data = if rng.coinflip(0.5) {
                    section.header_pointer_to_raw_data().saturating_add(delta)
                } else {
                    section.header_pointer_to_raw_data().saturating_sub(delta)
                };
            }
            7 => {
                section.tie_virtual_address_to_raw_data = !section.tie_virtual_address_to_raw_data;
            }
            _ => {
                section.pointer_to_relocations = rng.next_u64() as u32;
            }
        }

        RawMutationResult::Mutated
    }
}

impl InPlaceMutation for SectionHeaderMutations {
    fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
        Self::random_mutation(input, rng)
    }
}
