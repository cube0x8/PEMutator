use crate::io::{read_u16, read_u32};
use crate::pe::sections::{
    PeSection, find_section_containing_rva, read_c_string_at_rva, slice_at_rva,
};

use super::PeDataDirectory;

pub(crate) const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub(crate) const IMAGE_EXPORT_DIRECTORY_LEN: usize = 40;
pub(crate) const MAX_MUTATION_EXPORT_NAME_POINTERS: u32 = 4096;
pub(crate) const MAX_MUTATION_EXPORT_ADDRESS_TABLE_ENTRIES: u32 = 4096;
pub(crate) const MAX_MUTATION_EXPORT_ORDINAL_TABLE_ENTRIES: u32 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name_rva: u32,
    pub name: Option<String>,
    pub ordinal_base: u32,
    pub address_table_entries: u32,
    pub number_of_name_pointers: u32,
    pub export_address_table_rva: u32,
    pub name_pointer_rva: u32,
    pub ordinal_table_rva: u32,
}

impl ExportDirectory {
    pub(crate) fn parse(
        data_directories: &[PeDataDirectory],
        sections: &[PeSection],
    ) -> Option<Self> {
        let directory = data_directories.get(IMAGE_DIRECTORY_ENTRY_EXPORT)?;
        if directory.virtual_address == 0 {
            return None;
        }

        // The declared export directory size may itself be malformed.
        // We still attempt to parse the canonical export header layout and only
        // fail if the backing bytes are actually unavailable.
        let header = slice_at_rva(
            sections,
            directory.virtual_address,
            IMAGE_EXPORT_DIRECTORY_LEN,
        )?;
        let name_rva = read_u32(header, 12).ok()?;

        Some(Self {
            characteristics: read_u32(header, 0).ok()?,
            time_date_stamp: read_u32(header, 4).ok()?,
            major_version: read_u16(header, 8).ok()?,
            minor_version: read_u16(header, 10).ok()?,
            name_rva,
            name: read_c_string_at_rva(sections, name_rva),
            ordinal_base: read_u32(header, 16).ok()?,
            address_table_entries: read_u32(header, 20).ok()?,
            number_of_name_pointers: read_u32(header, 24).ok()?,
            export_address_table_rva: read_u32(header, 28).ok()?,
            name_pointer_rva: read_u32(header, 32).ok()?,
            ordinal_table_rva: read_u32(header, 36).ok()?,
        })
    }

    pub(crate) fn load_for_mutation(
        data_directories: &[PeDataDirectory],
        sections: &[PeSection],
    ) -> Option<Self> {
        let directory = data_directories.get(IMAGE_DIRECTORY_ENTRY_EXPORT)?;
        if directory.virtual_address == 0 || directory.size < IMAGE_EXPORT_DIRECTORY_LEN as u32 {
            return None;
        }

        let mut export = Self::parse(data_directories, sections)?;

        // Export mutations should only run when the backing RVAs still point into
        // materialized sections. We stay permissive by clamping counts to what is
        // actually readable instead of requiring a fully well-formed export table.
        let max_name_pointers = readable_table_entries(sections, export.name_pointer_rva, 4)?;
        export.number_of_name_pointers = export
            .number_of_name_pointers
            .min(max_name_pointers)
            .min(MAX_MUTATION_EXPORT_NAME_POINTERS);

        if export.number_of_name_pointers > 0 {
            let max_ordinals = readable_table_entries(sections, export.ordinal_table_rva, 2)?;
            export.number_of_name_pointers = export
                .number_of_name_pointers
                .min(max_ordinals)
                .min(MAX_MUTATION_EXPORT_ORDINAL_TABLE_ENTRIES);
        }

        if export.address_table_entries > 0 {
            let max_exports = readable_table_entries(sections, export.export_address_table_rva, 4)?;
            export.address_table_entries = export
                .address_table_entries
                .min(max_exports)
                .min(MAX_MUTATION_EXPORT_ADDRESS_TABLE_ENTRIES);
        } else if export.export_address_table_rva != 0
            && find_section_containing_rva(sections, export.export_address_table_rva).is_none()
        {
            return None;
        }

        export.name = if export.name_rva == 0 {
            None
        } else {
            read_c_string_at_rva(sections, export.name_rva)
        };

        Some(export)
    }
}

fn readable_table_entries(sections: &[PeSection], table_rva: u32, entry_size: u32) -> Option<u32> {
    if entry_size == 0 {
        return None;
    }
    let section = find_section_containing_rva(sections, table_rva)?;
    let relative = table_rva.checked_sub(section.virtual_address)? as usize;
    let available = section.raw_data.get(relative..)?.len();
    Some((available / entry_size as usize) as u32)
}

pub fn current_name_pointer_rva(export_directory: Option<&ExportDirectory>) -> Option<u32> {
    match export_directory {
        Some(export) => Some(export.name_pointer_rva),
        None => None,
    }
}
