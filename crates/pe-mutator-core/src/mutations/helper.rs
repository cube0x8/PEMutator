use crate::MutRng;
use crate::pe::{PeSection, section_span};

pub fn slightly_oversized_for_section<R: MutRng>(
    section: Option<&PeSection>,
    rng: &mut R,
    current_size: u32,
) -> u32 {
    section
        .map(|section| section_span(section).saturating_add(1 + rng.below(0x80) as u32))
        .unwrap_or(current_size.saturating_add(0x20).max(0x20))
}

pub fn overflowing_section_size<R: MutRng>(
    section: Option<&PeSection>,
    rng: &mut R,
    current_size: u32,
) -> u32 {
    section
        .map(|section| section_span(section).saturating_add(0x100 + rng.below(0x1000) as u32))
        .unwrap_or(
            current_size
                .max(0x1000)
                .saturating_add(rng.below(0x4000) as u32),
        )
}

pub fn huge_directory_size<R: MutRng>(rng: &mut R) -> u32 {
    0x10000 + rng.below(0x7fff_0000) as u32
}
