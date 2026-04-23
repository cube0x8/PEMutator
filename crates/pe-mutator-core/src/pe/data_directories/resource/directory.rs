use crate::core::io::{read_u16, read_u32};
use crate::pe::sections::{PeSection, slice_at_rva};

pub(crate) const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub(crate) const IMAGE_RESOURCE_DIRECTORY_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ResourceDirectory {
    pub characteristics: u32,
    pub timestamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub number_of_named_entries: u16,
    pub number_of_id_entries: u16,
}

impl ResourceDirectory {
    pub(crate) fn parse_at_rva(
        table_rva: u32,
        sections: &[PeSection],
    ) -> Option<ResourceDirectory> {
        let header = slice_at_rva(sections, table_rva, IMAGE_RESOURCE_DIRECTORY_LEN)?;

        Some(ResourceDirectory {
            characteristics: read_u32(header, 0).ok()?,
            timestamp: read_u32(header, 4).ok()?,
            major_version: read_u16(header, 8).ok()?,
            minor_version: read_u16(header, 10).ok()?,
            number_of_named_entries: read_u16(header, 12).ok()?,
            number_of_id_entries: read_u16(header, 14).ok()?,
        })
    }
}
