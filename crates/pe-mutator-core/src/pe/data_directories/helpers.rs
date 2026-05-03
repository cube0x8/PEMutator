use crate::io::{read_u16, read_u32};
use crate::pe::sections::{PeSection, find_section_containing_rva};

pub(crate) fn read_name_pointer_entry(
    sections: &[PeSection],
    table_rva: u32,
    index: usize,
) -> Option<u32> {
    let offset = index.checked_mul(4)?;
    let entry_rva = table_rva.checked_add(offset as u32)?;
    let section = find_section_containing_rva(sections, entry_rva)?;
    let relative = entry_rva.checked_sub(section.virtual_address)?;
    let start = relative as usize;
    let end = start.checked_add(4)?;
    if end > section.raw_data.len() {
        return None;
    }
    read_u32(&section.raw_data, start).ok()
}

pub(crate) fn read_export_address_table_entry(
    sections: &[PeSection],
    table_rva: u32,
    index: usize,
) -> Option<u32> {
    let offset = index.checked_mul(4)?;
    let entry_rva = table_rva.checked_add(offset as u32)?;
    let section = find_section_containing_rva(sections, entry_rva)?;
    let relative = entry_rva.checked_sub(section.virtual_address)?;
    let start = relative as usize;
    let end = start.checked_add(4)?;
    if end > section.raw_data.len() {
        return None;
    }
    read_u32(&section.raw_data, start).ok()
}

pub(crate) fn read_ordinal_table_entry(
    sections: &[PeSection],
    table_rva: u32,
    index: usize,
) -> Option<u16> {
    let offset = index.checked_mul(2)?;
    let entry_rva = table_rva.checked_add(offset as u32)?;
    let section = find_section_containing_rva(sections, entry_rva)?;
    let relative = entry_rva.checked_sub(section.virtual_address)?;
    let start = relative as usize;
    let end = start.checked_add(2)?;
    if end > section.raw_data.len() {
        return None;
    }
    read_u16(&section.raw_data, start).ok()
}
