use crate::pe::data_directories::PeDataDirectory;
use crate::pe::data_directories::resource::{
    ResourceDataEntry, ResourceDirectory, ResourceDirectoryEntry, ResourceDirectoryString,
};
use crate::pe::sections::{PeSection, slice_at_rva};

use super::directory::{IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_RESOURCE_DIRECTORY_LEN};
use super::entry::{IMAGE_RESOURCE_DIRECTORY_ENTRY_LEN, MAX_MUTATION_ENTRIES};

pub(crate) const MAX_RESOURCE_DIRECTORY_DEPTH: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ParsedResourceDirectory {
    pub header: ResourceDirectory,
    pub entries: Vec<ParsedResourceEntry>,
    pub table_offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ParsedResourceEntry {
    pub raw_entry: ResourceDirectoryEntry,
    pub name: ResourceEntryName,
    pub target: ResourceEntryTarget,
    pub entry_offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ResourceEntryName {
    Id(u32),
    String(ResourceDirectoryString),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ResourceEntryTarget {
    Directory(Box<ParsedResourceDirectory>),
    Data(ResourceDataEntry),
}

pub fn parse_resource_directory_tree(
    data_directories: &[PeDataDirectory],
    sections: &[PeSection],
) -> Option<ParsedResourceDirectory> {
    let directory = data_directories.get(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
    if directory.virtual_address == 0 {
        return None;
    }

    parse_resource_directory_tree_impl(directory.virtual_address, 0, 1, sections)
}

fn parse_resource_directory_tree_impl(
    resource_root_rva: u32,
    table_offset: u32,
    depth: u32,
    sections: &[PeSection],
) -> Option<ParsedResourceDirectory> {
    if depth > MAX_RESOURCE_DIRECTORY_DEPTH {
        return None;
    }

    let root_dir_to_parse = resource_root_rva.checked_add(table_offset)?;
    let root_directory = ResourceDirectory::parse_at_rva(root_dir_to_parse, sections)?;
    let mut parsed_root = ParsedResourceDirectory {
        header: root_directory,
        entries: Vec::new(),
        table_offset,
    };
    parse_resource_directory_entries(
        &mut parsed_root,
        resource_root_rva,
        table_offset,
        depth,
        sections,
    )?;
    Some(parsed_root)
}

fn parse_resource_directory_entries(
    parsed_directory: &mut ParsedResourceDirectory,
    root_resource_directory_rva: u32,
    current_table_offset: u32,
    depth: u32,
    sections: &[PeSection],
) -> Option<()> {
    let entry_count = u32::from(parsed_directory.header.number_of_named_entries)
        .checked_add(u32::from(parsed_directory.header.number_of_id_entries))?;

    if entry_count == 0 {
        return Some(());
    }

    if entry_count > MAX_MUTATION_ENTRIES {
        return None;
    }

    let entries_offset = current_table_offset.checked_add(IMAGE_RESOURCE_DIRECTORY_LEN as u32)?;
    let entries_size = entry_count.checked_mul(IMAGE_RESOURCE_DIRECTORY_ENTRY_LEN as u32)?;
    let entries_end = entries_offset.checked_add(entries_size)?;
    let entries_rva = root_resource_directory_rva.checked_add(entries_offset)?;

    slice_at_rva(sections, entries_rva, entries_size as usize)?;

    for entry_index in 0..entry_count {
        let raw_entry = ResourceDirectoryEntry::parse_resource_directory_entry(
            root_resource_directory_rva,
            current_table_offset,
            entry_index,
            sections,
        )?;

        let entry_offset = entries_offset
            .checked_add(entry_index.checked_mul(IMAGE_RESOURCE_DIRECTORY_ENTRY_LEN as u32)?)?;

        if entry_offset.checked_add(IMAGE_RESOURCE_DIRECTORY_ENTRY_LEN as u32)? > entries_end {
            return None;
        }

        let name = match raw_entry.name_offset() {
            Some(name_offset) => {
                let string_rva = root_resource_directory_rva.checked_add(name_offset)?;
                let string =
                    ResourceDirectoryString::parse_resource_directory_string(string_rva, sections)?;
                ResourceEntryName::String(string)
            }
            None => ResourceEntryName::Id(raw_entry.integer_id()?),
        };

        let target = match raw_entry.offset_to_directory() {
            Some(directory_offset) => {
                ResourceEntryTarget::Directory(Box::new(parse_resource_directory_tree_impl(
                    root_resource_directory_rva,
                    directory_offset,
                    depth.checked_add(1)?,
                    sections,
                )?))
            }
            None => {
                let data_entry_offset = raw_entry.offset_to_data_entry()?;
                let data_entry_rva = root_resource_directory_rva.checked_add(data_entry_offset)?;
                ResourceEntryTarget::Data(ResourceDataEntry::parse_at_rva(
                    data_entry_rva,
                    sections,
                )?)
            }
        };

        parsed_directory.entries.push(ParsedResourceEntry {
            raw_entry,
            name,
            target,
            entry_offset,
        });
    }

    Some(())
}
