use crate::core::{io::read_c_string_lossy, rng::MutRng};
use crate::pe::sections::PeSection;

pub fn find_section_containing_rva(sections: &[PeSection], rva: u32) -> Option<&PeSection> {
    sections.iter().find(|section| {
        let start = section.virtual_address;
        let end = start.saturating_add(section_span(section));
        rva >= start && rva < end
    })
}

pub fn find_section_containing_rva_mut(
    sections: &mut [PeSection],
    rva: u32,
) -> Option<&mut PeSection> {
    sections.iter_mut().find(|section| {
        let start = section.virtual_address;
        let end = start.saturating_add(section_span(section));
        rva >= start && rva < end
    })
}

pub fn read_string_at_rva(
    sections: &[PeSection],
    rva: u32,
    max_len: usize,
) -> Option<(String, bool)> {
    let section = find_section_containing_rva(sections, rva)?;
    let offset = rva.checked_sub(section.virtual_address)? as usize;
    read_c_string_lossy(&section.raw_data, offset, max_len)
}

pub fn pick_random_section<'a, R: MutRng>(
    sections: &'a [PeSection],
    rng: &mut R,
) -> Option<&'a PeSection> {
    if sections.is_empty() {
        None
    } else {
        Some(&sections[rng.below(sections.len())])
    }
}

pub fn section_span(section: &PeSection) -> u32 {
    section.virtual_size.max(section.size_of_raw_data()).max(1)
}
