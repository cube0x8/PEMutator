use crate::MutRng;
use crate::pe::{
    COMMON_SECTION_NAMES, PeSection, SPECIAL_SECTION_NAMES, find_section_containing_rva,
    pick_random_section, section_span,
};

const SMALL_RVA_DELTAS: [u32; 5] = [4, 8, 16, 32, 0x100];

pub fn apply_small_rva_delta<R: MutRng>(current_rva: u32, rng: &mut R) -> u32 {
    let delta = SMALL_RVA_DELTAS[rng.below(SMALL_RVA_DELTAS.len())];
    if rng.coinflip(0.5) {
        current_rva.saturating_add(delta)
    } else {
        current_rva.saturating_sub(delta)
    }
}

pub fn random_rva_in_section<R: MutRng>(section: &PeSection, rng: &mut R) -> u32 {
    let span = section_span(section).max(1);
    section
        .virtual_address
        .saturating_add(rng.below(span as usize) as u32)
}

pub fn rva_near_section_end<R: MutRng>(section: &PeSection, rng: &mut R) -> u32 {
    let span = section_span(section);
    let tail = span.min(0x40).max(1);
    section
        .virtual_address
        .saturating_add(span.saturating_sub(1 + rng.below(tail as usize) as u32))
}

pub fn rva_near_raw_end<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    let section = pick_random_section(sections, rng);
    if let Some(section) = section {
        let raw_end_rva = section
            .virtual_address
            .saturating_add(section.size_of_raw_data().max(1));
        raw_end_rva.saturating_sub(rng.below(0x20) as u32)
    } else {
        rng.below(0x20_000) as u32
    }
}

pub fn rva_outside_all_sections<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    let max_end = sections
        .iter()
        .map(|section| {
            section
                .virtual_address
                .saturating_add(section_span(section))
        })
        .max()
        .unwrap_or(0);
    max_end.saturating_add(0x100 + rng.below(0x4000) as u32)
}

pub fn rva_in_named_or_random_section<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    let matching: Vec<&PeSection> = sections
        .iter()
        .filter(|section| {
            let name = section.name_string();
            COMMON_SECTION_NAMES
                .iter()
                .chain(SPECIAL_SECTION_NAMES.iter())
                .any(|candidate| *candidate == name.as_bytes())
        })
        .collect();
    if !matching.is_empty() {
        return random_rva_in_section(matching[rng.below(matching.len())], rng);
    }

    pick_random_section(sections, rng)
        .map(|section| random_rva_in_section(section, rng))
        .unwrap_or_else(|| rng.below(0x20_000) as u32)
}

pub fn mutate_plausible_rva<R: MutRng>(
    current_rva: u32,
    sections: &[PeSection],
    rng: &mut R,
) -> u32 {
    let containing_section = find_section_containing_rva(sections, current_rva)
        .or_else(|| pick_random_section(sections, rng));

    match rng.below(4) {
        0 => containing_section
            .map(|section| random_rva_in_section(section, rng))
            .unwrap_or_else(|| current_rva.saturating_add(rng.below(0x200) as u32)),
        1 => containing_section
            .map(|section| section.virtual_address)
            .unwrap_or(current_rva),
        2 => containing_section
            .map(|section| rva_near_section_end(section, rng))
            .unwrap_or(current_rva),
        _ => apply_small_rva_delta(current_rva, rng),
    }
}

pub fn mutate_controlled_invalid_rva<R: MutRng>(sections: &[PeSection], rng: &mut R) -> u32 {
    match rng.below(4) {
        0 => 0,
        1 => rva_outside_all_sections(sections, rng),
        2 => rva_in_named_or_random_section(sections, rng),
        _ => rva_near_raw_end(sections, rng),
    }
}

pub fn mutate_havoc_rva<R: MutRng>(rng: &mut R) -> u32 {
    rng.next_u64() as u32
}
