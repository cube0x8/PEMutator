use crate::io::read_u32;
use crate::pe::sections::{PeSection, slice_at_rva};

pub(crate) const IMAGE_RESOURCE_DATA_ENTRY_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ResourceDataEntry {
    pub data_rva: u32,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
}

impl ResourceDataEntry {
    pub(crate) fn parse_at_rva(
        data_entry_rva: u32,
        sections: &[PeSection],
    ) -> Option<ResourceDataEntry> {
        let data_entry = slice_at_rva(sections, data_entry_rva, IMAGE_RESOURCE_DATA_ENTRY_LEN)?;

        Some(ResourceDataEntry {
            data_rva: read_u32(data_entry, 0).ok()?,
            size: read_u32(data_entry, 4).ok()?,
            code_page: read_u32(data_entry, 8).ok()?,
            reserved: read_u32(data_entry, 12).ok()?,
        })
    }
}
