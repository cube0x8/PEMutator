use crate::core::io::{read_u16, read_u32};
use crate::pe::sections::{PeSection, slice_at_rva};

use super::directory::IMAGE_RESOURCE_DIRECTORY_LEN;

pub(crate) const MAX_MUTATION_ENTRIES: u32 = 4096;
pub(crate) const IMAGE_RESOURCE_DIRECTORY_ENTRY_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ResourceDirectoryEntry {
    pub name_or_id: u32,
    pub offset_to_data_or_directory: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ResourceDirectoryString {
    pub length: u16,
    pub name_string: String,
}

impl ResourceDirectoryEntry {
    fn is_named(&self) -> bool {
        self.name_or_id & 0x8000_0000 != 0
    }

    fn is_directory(&self) -> bool {
        self.offset_to_data_or_directory & 0x8000_0000 != 0
    }

    pub(crate) fn name_offset(&self) -> Option<u32> {
        self.is_named().then_some(self.name_or_id & 0x7fff_ffff)
    }

    pub(crate) fn integer_id(&self) -> Option<u32> {
        (!self.is_named()).then_some(self.name_or_id)
    }

    pub(crate) fn offset_to_directory(&self) -> Option<u32> {
        self.is_directory()
            .then_some(self.offset_to_data_or_directory & 0x7fff_ffff)
    }

    pub(crate) fn offset_to_data_entry(&self) -> Option<u32> {
        (!self.is_directory()).then_some(self.offset_to_data_or_directory)
    }

    pub(crate) fn parse_resource_directory_entry(
        table_rva: u32,
        table_offset: u32,
        entry_index: u32,
        sections: &[PeSection],
    ) -> Option<ResourceDirectoryEntry> {
        let entries_offset = table_offset.checked_add(IMAGE_RESOURCE_DIRECTORY_LEN as u32)?;
        let entry_offset = entries_offset
            .checked_add(entry_index.checked_mul(IMAGE_RESOURCE_DIRECTORY_ENTRY_LEN as u32)?)?;
        let entry_rva = table_rva.checked_add(entry_offset)?;
        let entry_bytes = slice_at_rva(sections, entry_rva, IMAGE_RESOURCE_DIRECTORY_ENTRY_LEN)?;

        Some(ResourceDirectoryEntry {
            name_or_id: read_u32(entry_bytes, 0).ok()?,
            offset_to_data_or_directory: read_u32(entry_bytes, 4).ok()?,
        })
    }
}

impl ResourceDirectoryString {
    pub(crate) fn parse_resource_directory_string(
        string_rva: u32,
        sections: &[PeSection],
    ) -> Option<ResourceDirectoryString> {
        let string_bytes = slice_at_rva(
            sections, string_rva, 2, // We only need to read the length first
        )?;

        let length = read_u16(string_bytes, 0).ok()?;
        let name_string_bytes = slice_at_rva(
            sections,
            string_rva.checked_add(2)?,
            length as usize * 2, // 2 bytes for utf char
        )?;

        let name_string = String::from_utf16_lossy(
            &name_string_bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<u16>>(),
        );

        Some(ResourceDirectoryString {
            length,
            name_string,
        })
    }
}
