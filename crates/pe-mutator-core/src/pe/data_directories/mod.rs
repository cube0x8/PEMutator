pub mod export;
mod helpers;
pub mod resource;

use crate::io::{read_u16, read_u32};
use crate::pe::pe::OPTIONAL_MAGIC_PE32_PLUS;

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PeDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub(crate) fn number_of_rva_and_sizes_offset(optional_magic: u16) -> usize {
    match optional_magic {
        OPTIONAL_MAGIC_PE32_PLUS => 0x6c,
        _ => 0x5c,
    }
}

pub(crate) fn data_directories_offset(optional_magic: u16) -> usize {
    match optional_magic {
        OPTIONAL_MAGIC_PE32_PLUS => 0x70,
        _ => 0x60,
    }
}

pub(crate) fn optional_header_size_for_data_directories(
    optional_magic: u16,
    entry_count: usize,
) -> usize {
    data_directories_offset(optional_magic).saturating_add(entry_count.saturating_mul(8))
}

pub(crate) fn parse_data_directories(optional_header: &[u8]) -> Vec<PeDataDirectory> {
    let Ok(optional_magic) = read_u16(optional_header, 0) else {
        return Vec::new();
    };
    let Ok(number_of_rva_and_sizes) = read_u32(
        optional_header,
        number_of_rva_and_sizes_offset(optional_magic),
    ) else {
        return Vec::new();
    };
    let data_directories_offset = data_directories_offset(optional_magic);
    let available_entries = optional_header
        .len()
        .saturating_sub(data_directories_offset)
        / 8;
    let entry_count = (number_of_rva_and_sizes as usize).min(available_entries);
    let mut data_directories = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let entry_offset = data_directories_offset + index * 8;
        let Ok(virtual_address) = read_u32(optional_header, entry_offset) else {
            break;
        };
        let Ok(size) = read_u32(optional_header, entry_offset + 4) else {
            break;
        };
        data_directories.push(PeDataDirectory {
            virtual_address,
            size,
        });
    }
    data_directories
}

pub use export::ExportDirectory;
pub(crate) use helpers::{
    read_export_address_table_entry, read_name_pointer_entry, read_ordinal_table_entry,
};
pub use resource::{ParsedResourceDirectory, ResourceDirectory, parse_resource_directory_tree};
