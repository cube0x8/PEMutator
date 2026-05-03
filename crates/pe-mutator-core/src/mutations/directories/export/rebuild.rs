use crate::MutRng;
use crate::io::{write_u16_into, write_u32_into};
use crate::pe::PeInput;
use crate::pe::data_directories::{ExportDirectory, PeDataDirectory};
use crate::pe::data_directories::export::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_EXPORT_DIRECTORY_LEN,
};
use crate::pe::sections::{IMAGE_SCN_MEM_EXECUTE, PeSection};

const DEFAULT_DLL_NAME: &[u8] = b"pe-mutator.dll\0";
const DEFAULT_EXPORT_NAME: &[u8] = b"Exported\0";
const DEFAULT_FUNCTION_STUB: &[u8] = &[0xc3];
const RVA_ALIGN: usize = 4;
const ORDINAL_ALIGN: usize = 2;

pub(super) fn rebuild_minimal_export_directory<R: MutRng>(
    input: &mut PeInput,
    rng: &mut R,
) -> bool {
    let Some(section_index) = pick_rebuild_section_index(&input.sections, rng) else {
        return false;
    };
    ensure_export_directory_entry(input);

    let section = &mut input.sections[section_index];
    let start = align_up(section.raw_data.len(), RVA_ALIGN);
    if section.raw_data.len() < start {
        section.raw_data.resize(start, 0);
    }

    let base_rva = section.virtual_address.saturating_add(start as u32);
    let mut blob = vec![0_u8; IMAGE_EXPORT_DIRECTORY_LEN];

    let dll_name_offset = blob.len();
    blob.extend_from_slice(DEFAULT_DLL_NAME);

    let export_name_offset = blob.len();
    blob.extend_from_slice(DEFAULT_EXPORT_NAME);

    align_blob(&mut blob, RVA_ALIGN);
    let eat_offset = blob.len();
    blob.extend_from_slice(&[0_u8; 4]);

    align_blob(&mut blob, RVA_ALIGN);
    let name_pointer_offset = blob.len();
    blob.extend_from_slice(&[0_u8; 4]);

    align_blob(&mut blob, ORDINAL_ALIGN);
    let ordinal_offset = blob.len();
    blob.extend_from_slice(&[0_u8; 2]);

    let function_stub_offset = blob.len();
    blob.extend_from_slice(DEFAULT_FUNCTION_STUB);

    let directory_rva = base_rva;
    let dll_name_rva = base_rva.saturating_add(dll_name_offset as u32);
    let export_name_rva = base_rva.saturating_add(export_name_offset as u32);
    let eat_rva = base_rva.saturating_add(eat_offset as u32);
    let name_pointer_rva = base_rva.saturating_add(name_pointer_offset as u32);
    let ordinal_rva = base_rva.saturating_add(ordinal_offset as u32);
    let function_stub_rva = base_rva.saturating_add(function_stub_offset as u32);

    write_u32_into(&mut blob, 0, 0);
    write_u32_into(&mut blob, 4, 0);
    write_u16_into(&mut blob, 8, 0);
    write_u16_into(&mut blob, 10, 0);
    write_u32_into(&mut blob, 12, dll_name_rva);
    write_u32_into(&mut blob, 16, 1);
    write_u32_into(&mut blob, 20, 1);
    write_u32_into(&mut blob, 24, 1);
    write_u32_into(&mut blob, 28, eat_rva);
    write_u32_into(&mut blob, 32, name_pointer_rva);
    write_u32_into(&mut blob, 36, ordinal_rva);
    write_u32_into(&mut blob, eat_offset, function_stub_rva);
    write_u32_into(&mut blob, name_pointer_offset, export_name_rva);
    write_u16_into(&mut blob, ordinal_offset, 0);

    section.raw_data.extend_from_slice(&blob);
    section.virtual_size = section.virtual_size.max(section.raw_data.len() as u32);

    input.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT] = PeDataDirectory {
        virtual_address: directory_rva,
        size: blob.len() as u32,
    };
    input.export_directory =
        ExportDirectory::load_for_mutation(&input.data_directories, &input.sections);

    input.export_directory.is_some()
}

fn ensure_export_directory_entry(input: &mut PeInput) {
    if input.data_directories.len() <= IMAGE_DIRECTORY_ENTRY_EXPORT {
        input
            .data_directories
            .resize(IMAGE_DIRECTORY_ENTRY_EXPORT + 1, PeDataDirectory::default());
    }
}

fn pick_rebuild_section_index<R: MutRng>(sections: &[PeSection], rng: &mut R) -> Option<usize> {
    if sections.is_empty() {
        return None;
    }

    let preferred: Vec<_> = sections
        .iter()
        .enumerate()
        .filter_map(|(index, section)| {
            ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0).then_some(index)
        })
        .collect();

    let candidates = if preferred.is_empty() {
        (0..sections.len()).collect::<Vec<_>>()
    } else {
        preferred
    };

    Some(candidates[rng.below(candidates.len())])
}

fn align_up(value: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        value
    } else {
        let remainder = value % alignment;
        if remainder == 0 {
            value
        } else {
            value + (alignment - remainder)
        }
    }
}

fn align_blob(blob: &mut Vec<u8>, alignment: usize) {
    let aligned = align_up(blob.len(), alignment);
    if blob.len() < aligned {
        blob.resize(aligned, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::rebuild_minimal_export_directory;
    use crate::SimpleRng;
    use crate::io::write_u32_into;
    use crate::pe::PeInput;
    use crate::pe::data_directories::ExportDirectory;
    use crate::pe::data_directories::export::{
        IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_EXPORT_DIRECTORY_LEN,
    };
    use crate::pe::sections::find_section_containing_rva;

    #[test]
    fn rebuild_creates_a_minimal_valid_export_directory_when_missing() {
        let mut input = PeInput::template(crate::pe::IMAGE_FILE_MACHINE_AMD64);
        let mut rng = SimpleRng::new(7);

        assert!(rebuild_minimal_export_directory(&mut input, &mut rng));

        let export = ExportDirectory::load_for_mutation(&input.data_directories, &input.sections)
            .expect("rebuild should materialize a readable export directory");
        let directory = &input.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];

        assert_ne!(directory.virtual_address, 0);
        assert!(directory.size >= IMAGE_EXPORT_DIRECTORY_LEN as u32);
        assert_eq!(export.number_of_name_pointers, 1);
        assert_eq!(export.address_table_entries, 1);
        assert_eq!(export.ordinal_base, 1);
        assert!(find_section_containing_rva(&input.sections, directory.virtual_address).is_some());
        assert!(find_section_containing_rva(&input.sections, export.name_pointer_rva).is_some());
        assert!(find_section_containing_rva(&input.sections, export.ordinal_table_rva).is_some());
        assert!(
            find_section_containing_rva(&input.sections, export.export_address_table_rva).is_some()
        );
    }

    #[test]
    fn rebuild_replaces_invalid_export_table_rvas_with_readable_defaults() {
        let mut input = PeInput::template(crate::pe::IMAGE_FILE_MACHINE_AMD64);
        let mut rng = SimpleRng::new(11);
        assert!(rebuild_minimal_export_directory(&mut input, &mut rng));

        let export_rva = input.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
        let section = input
            .sections
            .iter_mut()
            .find(|section| {
                export_rva >= section.virtual_address
                    && export_rva
                        < section
                            .virtual_address
                            .saturating_add(section.raw_data.len() as u32)
            })
            .expect("rebuilt export should live inside a section");
        let start = (export_rva - section.virtual_address) as usize;
        write_u32_into(&mut section.raw_data, start + 28, u32::MAX - 8);
        write_u32_into(&mut section.raw_data, start + 32, u32::MAX - 4);
        write_u32_into(&mut section.raw_data, start + 36, u32::MAX - 2);

        input.export_directory =
            ExportDirectory::load_for_mutation(&input.data_directories, &input.sections);
        assert!(input.export_directory.is_none());

        assert!(rebuild_minimal_export_directory(&mut input, &mut rng));

        let rebuilt = ExportDirectory::load_for_mutation(&input.data_directories, &input.sections)
            .expect("rebuild should restore readable export tables");
        assert!(find_section_containing_rva(&input.sections, rebuilt.name_pointer_rva).is_some());
        assert!(find_section_containing_rva(&input.sections, rebuilt.ordinal_table_rva).is_some());
        assert!(
            find_section_containing_rva(&input.sections, rebuilt.export_address_table_rva)
                .is_some()
        );
    }
}
