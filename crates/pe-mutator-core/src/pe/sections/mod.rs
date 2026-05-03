pub mod constants;
pub mod helpers;
use crate::error::Error;
use crate::io::{read_u16, read_u32};
use crate::pe::sections::constants::SECTION_HEADER_LEN;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PeSection {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data: Vec<u8>,
    #[serde(default)]
    pub declared_pointer_to_raw_data: u32,
    #[serde(default)]
    pub declared_size_of_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
    pub tie_virtual_address_to_raw_data: bool,
}

impl PeSection {
    pub fn new(name: &[u8], virtual_address: u32, raw_data: Vec<u8>, characteristics: u32) -> Self {
        let mut section_name = [0_u8; 8];
        let copy_len = name.len().min(section_name.len());
        section_name[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            name: section_name,
            virtual_size: raw_data.len() as u32,
            virtual_address,
            declared_pointer_to_raw_data: 0,
            declared_size_of_raw_data: raw_data.len() as u32,
            raw_data,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics,
            tie_virtual_address_to_raw_data: false,
        }
    }

    pub fn size_of_raw_data(&self) -> u32 {
        self.raw_data.len() as u32
    }

    pub fn header_size_of_raw_data(&self) -> u32 {
        if self.declared_size_of_raw_data == 0 && !self.raw_data.is_empty() {
            self.raw_data.len() as u32
        } else {
            self.declared_size_of_raw_data
        }
    }

    pub fn header_pointer_to_raw_data(&self) -> u32 {
        self.declared_pointer_to_raw_data
    }

    pub fn name_string(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SectionLayout {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_relocations: u32,
}

pub(crate) fn slice_at_rva(sections: &[PeSection], rva: u32, size: usize) -> Option<&[u8]> {
    let size = u32::try_from(size).ok()?;
    for section in sections {
        let section_start = section.virtual_address;
        let available_size = section.raw_data.len() as u32;
        let section_end = section_start.checked_add(available_size)?;
        if rva < section_start || rva > section_end {
            continue;
        }
        let offset = rva.checked_sub(section_start)?;
        let end_offset = offset.checked_add(size)?;
        if end_offset > available_size {
            continue;
        }
        let start = offset as usize;
        let end = end_offset as usize;
        return Some(&section.raw_data[start..end]);
    }
    None
}

pub(crate) fn read_c_string_at_rva(sections: &[PeSection], rva: u32) -> Option<String> {
    for section in sections {
        let section_start = section.virtual_address;
        let available_size = section.raw_data.len() as u32;
        let section_end = section_start.checked_add(available_size)?;
        if rva < section_start || rva >= section_end {
            continue;
        }
        let offset = rva.checked_sub(section_start)? as usize;
        let bytes = section.raw_data.get(offset..)?;
        let nul = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        return Some(String::from_utf8_lossy(&bytes[..nul]).into_owned());
    }
    None
}

pub(crate) fn parse_sections(
    number_of_sections: usize,
    section_table_offset: usize,
    bytes: &[u8],
) -> Result<Vec<PeSection>, crate::error::Error> {
    let mut sections = Vec::with_capacity(number_of_sections);

    for index in 0..number_of_sections {
        let base = section_table_offset + index * SECTION_HEADER_LEN;
        let mut name = [0_u8; 8];
        name.copy_from_slice(&bytes[base..base + 8]);
        let virtual_size = read_u32(bytes, base + 8)?;
        let virtual_address = read_u32(bytes, base + 12)?;
        let size_of_raw_data = read_u32(bytes, base + 16)?;
        let pointer_to_raw_data = read_u32(bytes, base + 20)?;
        let pointer_to_relocations = read_u32(bytes, base + 24)?;
        let pointer_to_linenumbers = read_u32(bytes, base + 28)?;
        let number_of_relocations = read_u16(bytes, base + 32)?;
        let number_of_linenumbers = read_u16(bytes, base + 34)?;
        let characteristics = read_u32(bytes, base + 36)?;

        let raw_data = if size_of_raw_data == 0 {
            Vec::new()
        } else {
            let start = pointer_to_raw_data as usize;
            let end = start
                .checked_add(size_of_raw_data as usize)
                .ok_or_else(|| Error::illegal_argument("section raw data overflows"))?;
            let actual_end = end.min(bytes.len());
            if start >= bytes.len() {
                Vec::new()
            } else {
                bytes[start..actual_end].to_vec()
            }
        };

        sections.push(PeSection {
            name,
            virtual_size,
            virtual_address,
            raw_data,
            declared_pointer_to_raw_data: pointer_to_raw_data,
            declared_size_of_raw_data: size_of_raw_data,
            pointer_to_relocations,
            pointer_to_linenumbers,
            number_of_relocations,
            number_of_linenumbers,
            characteristics,
            tie_virtual_address_to_raw_data: virtual_address == pointer_to_raw_data,
        });
    }
    Ok(sections)
}

pub use constants::{
    COMMON_SECTION_NAMES, DATA_SECTION_NAMES, EXEC_SECTION_NAMES, IMAGE_SCN_MEM_EXECUTE,
    MISC_SECTION_NAMES, SECTION_CHARACTERISTIC_FLAGS, SECTION_CHARACTERISTIC_MUTATION_BITS,
    SECTION_NAME_DICTIONARY, SPECIAL_SECTION_NAMES, VALID_SECTION_NAMES,
};
pub use helpers::*;
