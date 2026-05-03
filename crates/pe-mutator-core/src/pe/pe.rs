use std::fmt;

use super::arch::{canonical_optional_header_size, expected_optional_magic, infer_code_arch};
use super::data_directories::resource::ResourceEntryTarget;
use super::data_directories::{
    ExportDirectory, ParsedResourceDirectory, PeDataDirectory, data_directories_offset,
    number_of_rva_and_sizes_offset, optional_header_size_for_data_directories,
    parse_data_directories, parse_resource_directory_tree,
};
use super::sections::{PeSection, SectionLayout, read_c_string_at_rva, slice_at_rva};
use super::template::{DEFAULT_PE_OFFSET, DOS_MAGIC, default_dos_stub};
use crate::error::Error;
use crate::io::{read_u16, read_u32, write_u16, write_u16_into, write_u32, write_u32_into};
use crate::mutations::budget::PeSizeBudget;
use crate::pe::parse_sections;
use crate::pe::sections::constants::SECTION_HEADER_LEN;
use crate::utils::align_up;

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

pub const OPTIONAL_MAGIC_PE32: u16 = 0x10b;
pub const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x20b;

const PE_MAGIC: [u8; 4] = *b"PE\0\0";
const DOS_HEADER_LEN: usize = 0x40;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PeInput {
    pub dos_stub: Vec<u8>,
    pub machine: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub characteristics: u16,
    pub optional_header: Vec<u8>,
    #[serde(default)]
    pub data_directories: Vec<PeDataDirectory>,
    #[serde(default)]
    pub export_directory: Option<ExportDirectory>,
    pub resource_directory: Option<ParsedResourceDirectory>,
    pub declared_optional_header_size: u16,
    pub sections: Vec<PeSection>,
    pub overlay: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeArch {
    X86,
    X64,
    Arm32,
    Arm64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeLayout {
    pub pe_offset: u32,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub entry_point: u32,
    pub sections: Vec<SectionLayout>,
    pub overlay_offset: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PeSizeLimits {
    pub max_materialized_size: Option<usize>,
    pub max_serialized_size: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PeSerializationConfig {
    pub size_limits: PeSizeLimits,
}

impl PeInput {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < DOS_HEADER_LEN {
            return Err(Error::illegal_argument("file is too small to be a PE"));
        }
        if bytes[..2] != b"MZ"[..] {
            return Err(Error::illegal_argument("missing DOS MZ header"));
        }

        let pe_offset = read_u32(bytes, 0x3c)? as usize;
        if pe_offset + 4 + 20 > bytes.len() {
            return Err(Error::illegal_argument("PE header points outside the file"));
        }
        if bytes[pe_offset..pe_offset + 4] != PE_MAGIC {
            return Err(Error::illegal_argument("missing PE signature"));
        }

        let coff_offset = pe_offset + 4;
        let machine = read_u16(bytes, coff_offset)?;
        let number_of_sections = read_u16(bytes, coff_offset + 2)? as usize;
        let time_date_stamp = read_u32(bytes, coff_offset + 4)?;
        let pointer_to_symbol_table = read_u32(bytes, coff_offset + 8)?;
        let number_of_symbols = read_u32(bytes, coff_offset + 12)?;
        let declared_optional_header_size = read_u16(bytes, coff_offset + 16)?;
        let characteristics = read_u16(bytes, coff_offset + 18)?;

        let optional_offset = coff_offset + 20;
        let section_table_offset = optional_offset + declared_optional_header_size as usize;
        if section_table_offset > bytes.len() {
            return Err(Error::illegal_argument(
                "optional header points outside the file",
            ));
        }
        if section_table_offset + number_of_sections * SECTION_HEADER_LEN > bytes.len() {
            return Err(Error::illegal_argument(
                "section table points outside the file",
            ));
        }

        let optional_header = bytes[optional_offset..section_table_offset].to_vec();
        let data_directories = parse_data_directories(&optional_header);
        let dos_stub = bytes[..pe_offset].to_vec();

        let sections = parse_sections(number_of_sections, section_table_offset, bytes)?;
        let overlay_start = sections
            .iter()
            .fold(section_table_offset, |max_end, section| {
                let start = section.header_pointer_to_raw_data() as usize;
                if section.header_size_of_raw_data() == 0 || start >= bytes.len() {
                    return max_end;
                }

                let end = start
                    .saturating_add(section.header_size_of_raw_data() as usize)
                    .min(bytes.len());
                max_end.max(end)
            });

        let overlay = if overlay_start < bytes.len() {
            bytes[overlay_start..].to_vec()
        } else {
            Vec::new()
        };
        let export_directory = ExportDirectory::parse(&data_directories, &sections);
        let resource_directory = parse_resource_directory_tree(&data_directories, &sections);

        Ok(Self {
            dos_stub,
            machine,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            characteristics,
            optional_header,
            data_directories,
            export_directory,
            resource_directory,
            declared_optional_header_size,
            sections,
            overlay,
        })
    }

    pub fn template(machine: u16) -> Self {
        let canonical_optional = canonical_optional_header_size(machine);
        let optional_magic = expected_optional_magic(machine);
        let file_alignment = 0x200_u32;
        let section_alignment = 0x1000_u32;
        let data_directories = vec![PeDataDirectory::default(); 16];

        let mut optional_header = vec![0_u8; canonical_optional];
        write_u16_into(&mut optional_header, 0x00, optional_magic);
        optional_header[0x02] = 0x0e;
        optional_header[0x03] = 0x00;
        write_u32_into(&mut optional_header, 0x10, 0x1000);
        write_u32_into(&mut optional_header, 0x20, section_alignment);
        write_u32_into(&mut optional_header, 0x24, file_alignment);
        write_u16_into(&mut optional_header, 0x44, 3);
        write_u32_into(
            &mut optional_header,
            number_of_rva_and_sizes_offset(optional_magic),
            data_directories.len() as u32,
        );

        let dos_stub = default_dos_stub();
        let text = PeSection::new(
            b".text",
            0x1000,
            vec![0x55, 0x8b, 0xec, 0x90, 0x90, 0xc3],
            0x6000_0020,
        );
        let data = PeSection::new(b".data", 0x2000, vec![0x41, 0x42, 0x43, 0x44], 0xc000_0040);

        Self {
            dos_stub,
            machine,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            characteristics: 0x210e,
            optional_header,
            data_directories,
            export_directory: None,
            resource_directory: None,
            declared_optional_header_size: canonical_optional as u16,
            sections: vec![text, data],
            overlay: Vec::new(),
        }
    }

    pub fn summary(&self) -> PeSummary<'_> {
        PeSummary(self)
    }

    pub fn materialized_size(&self) -> usize {
        self.dos_stub.len()
            + self.optional_header.len()
            + self.overlay.len()
            + self
                .sections
                .iter()
                .map(|section| section.raw_data.len())
                .sum::<usize>()
    }

    pub fn canonical_optional_header_size(&self) -> usize {
        canonical_optional_header_size(self.machine)
    }

    pub fn expected_optional_magic(&self) -> u16 {
        expected_optional_magic(self.machine)
    }

    pub fn infer_code_arch(&self) -> Option<CodeArch> {
        infer_code_arch(self.machine, self.optional_magic())
    }

    pub fn ensure_coherent_architecture(&mut self) {
        self.ensure_coherent_architecture_impl(None)
            .expect("unbounded optional header growth should never fail");
    }

    pub fn ensure_coherent_architecture_with_budget(
        &mut self,
        budget: &mut PeSizeBudget,
    ) -> Result<(), Error> {
        self.ensure_coherent_architecture_impl(Some(budget))
    }

    fn ensure_coherent_architecture_impl(
        &mut self,
        mut budget: Option<&mut PeSizeBudget>,
    ) -> Result<(), Error> {
        let canonical_size = self.canonical_optional_header_size();
        if self.data_directories.is_empty() {
            self.data_directories = parse_data_directories(&self.optional_header);
        }
        self.export_directory = ExportDirectory::parse(&self.data_directories, &self.sections);
        self.resource_directory =
            parse_resource_directory_tree(&self.data_directories, &self.sections);
        match budget.as_deref_mut() {
            Some(budget) => {
                self.set_optional_magic_with_budget(self.expected_optional_magic(), budget)?
            }
            None => self.set_optional_magic(self.expected_optional_magic()),
        }
        let required_optional_size = self.minimum_optional_header_size();
        match budget.as_deref_mut() {
            Some(budget) => self.ensure_optional_field_with_budget(
                required_optional_size.max(canonical_size),
                budget,
            )?,
            None => self.ensure_optional_field(required_optional_size.max(canonical_size)),
        }
        if (self.declared_optional_header_size as usize)
            < required_optional_size.max(canonical_size)
        {
            self.declared_optional_header_size = required_optional_size.max(canonical_size) as u16;
        }
        if self.file_alignment() == 0 {
            match budget.as_deref_mut() {
                Some(budget) => self.set_file_alignment_with_budget(0x200, budget)?,
                None => self.set_file_alignment(0x200),
            }
        }
        if self.section_alignment() == 0 {
            match budget.as_deref_mut() {
                Some(budget) => self.set_section_alignment_with_budget(0x1000, budget)?,
                None => self.set_section_alignment(0x1000),
            }
        }
        Ok(())
    }

    pub fn optional_magic(&self) -> u16 {
        self.optional_header
            .get(0..2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .unwrap_or(0)
    }

    pub fn set_optional_magic(&mut self, magic: u16) {
        self.ensure_optional_field(2);
        write_u16_into(&mut self.optional_header, 0x00, magic);
    }

    pub fn set_optional_magic_with_budget(
        &mut self,
        magic: u16,
        budget: &mut PeSizeBudget,
    ) -> Result<(), Error> {
        self.ensure_optional_field_with_budget(2, budget)?;
        write_u16_into(&mut self.optional_header, 0x00, magic);
        Ok(())
    }

    pub fn entry_point(&self) -> u32 {
        self.read_optional_u32(0x10).unwrap_or(0)
    }

    pub fn set_entry_point(&mut self, entry_point: u32) {
        self.ensure_optional_field(0x14);
        write_u32_into(&mut self.optional_header, 0x10, entry_point);
    }

    pub fn set_entry_point_with_budget(
        &mut self,
        entry_point: u32,
        budget: &mut PeSizeBudget,
    ) -> Result<(), Error> {
        self.ensure_optional_field_with_budget(0x14, budget)?;
        write_u32_into(&mut self.optional_header, 0x10, entry_point);
        Ok(())
    }

    pub fn section_alignment(&self) -> u32 {
        self.read_optional_u32(0x20).unwrap_or(0x1000)
    }

    pub fn set_section_alignment(&mut self, alignment: u32) {
        self.ensure_optional_field(0x24);
        write_u32_into(&mut self.optional_header, 0x20, alignment.max(1));
    }

    pub fn set_section_alignment_with_budget(
        &mut self,
        alignment: u32,
        budget: &mut PeSizeBudget,
    ) -> Result<(), Error> {
        self.ensure_optional_field_with_budget(0x24, budget)?;
        write_u32_into(&mut self.optional_header, 0x20, alignment.max(1));
        Ok(())
    }

    pub fn file_alignment(&self) -> u32 {
        self.read_optional_u32(0x24).unwrap_or(0x200)
    }

    pub fn set_file_alignment(&mut self, alignment: u32) {
        self.ensure_optional_field(0x28);
        write_u32_into(&mut self.optional_header, 0x24, alignment.max(1));
    }

    pub fn set_file_alignment_with_budget(
        &mut self,
        alignment: u32,
        budget: &mut PeSizeBudget,
    ) -> Result<(), Error> {
        self.ensure_optional_field_with_budget(0x28, budget)?;
        write_u32_into(&mut self.optional_header, 0x24, alignment.max(1));
        Ok(())
    }

    pub fn entry_section_index(&self) -> Option<usize> {
        let entry = self.entry_point();
        self.sections.iter().position(|section| {
            let start = section.virtual_address;
            let size = section.virtual_size.max(section.size_of_raw_data());
            let end = start.saturating_add(size);
            entry >= start && entry < end
        })
    }

    pub fn entry_bytes(&self) -> Option<&[u8]> {
        let entry = self.entry_point();
        let section = self.entry_section_index()?;
        let section = &self.sections[section];
        let offset = entry.checked_sub(section.virtual_address)? as usize;
        if offset >= section.raw_data.len() {
            return None;
        }
        let end = (offset + 128).min(section.raw_data.len());
        Some(&section.raw_data[offset..end])
    }

    pub fn data_directory(&self, index: usize) -> Option<&PeDataDirectory> {
        self.data_directories.get(index)
    }

    pub fn slice_at_rva(&self, rva: u32, size: usize) -> Option<&[u8]> {
        slice_at_rva(&self.sections, rva, size)
    }

    pub fn string_at_rva(&self, rva: u32) -> Option<String> {
        read_c_string_at_rva(&self.sections, rva)
    }

    pub fn layout(&self) -> Result<PeLayout, Error> {
        let mut normalized = self.clone();
        normalized.ensure_coherent_architecture();

        let pe_offset = normalized
            .dos_stub
            .len()
            .max(DEFAULT_PE_OFFSET)
            .max(DOS_HEADER_LEN) as u32;
        let file_alignment = normalized.file_alignment().max(1);
        let section_alignment = normalized.section_alignment().max(1);
        let declared_optional_size = normalized
            .declared_optional_header_size
            .max(normalized.canonical_optional_header_size() as u16)
            as u32;
        let section_table_size = normalized.sections.len() as u32 * SECTION_HEADER_LEN as u32;
        let raw_headers_end = pe_offset + 4 + 20 + declared_optional_size + section_table_size;
        let size_of_headers = align_up(raw_headers_end, file_alignment);

        let mut raw_cursor = size_of_headers;
        let mut next_virtual_address = align_up(0x1000, section_alignment);
        let mut sections = Vec::with_capacity(normalized.sections.len());

        for section in &normalized.sections {
            let mut pointer_to_raw_data = section.header_pointer_to_raw_data();
            if !section.raw_data.is_empty() && pointer_to_raw_data == 0 {
                raw_cursor = align_up(raw_cursor, file_alignment);
                let start = raw_cursor;
                raw_cursor = raw_cursor.saturating_add(section.raw_data.len() as u32);
                pointer_to_raw_data = start;
            }

            let size_of_raw_data = section.header_size_of_raw_data();
            let materialized_end = if section.raw_data.is_empty() || pointer_to_raw_data == 0 {
                0
            } else {
                pointer_to_raw_data.saturating_add(section.raw_data.len() as u32)
            };
            raw_cursor = raw_cursor.max(align_up(materialized_end, file_alignment));

            let virtual_address =
                if section.tie_virtual_address_to_raw_data && pointer_to_raw_data != 0 {
                    pointer_to_raw_data
                } else {
                    if section.virtual_address == 0 {
                        next_virtual_address
                    } else {
                        align_up(section.virtual_address, section_alignment)
                    }
                };

            let virtual_size = section.virtual_size.max(section.size_of_raw_data());
            next_virtual_address = align_up(
                virtual_address.saturating_add(virtual_size.max(1)),
                section_alignment,
            );

            sections.push(SectionLayout {
                name: section.name_string(),
                virtual_address,
                virtual_size,
                pointer_to_raw_data,
                size_of_raw_data,
                pointer_to_relocations: section.pointer_to_relocations,
            });
        }

        let last_end = sections
            .iter()
            .zip(normalized.sections.iter())
            .map(|(layout_section, section)| {
                if layout_section.pointer_to_raw_data == 0 || section.raw_data.is_empty() {
                    size_of_headers
                } else {
                    layout_section
                        .pointer_to_raw_data
                        .saturating_add(section.raw_data.len() as u32)
                }
            })
            .max()
            .unwrap_or(size_of_headers);
        let overlay_offset = last_end;
        let size_of_image = sections
            .iter()
            .map(|section| {
                align_up(
                    section
                        .virtual_address
                        .saturating_add(section.virtual_size.max(1)),
                    section_alignment,
                )
            })
            .max()
            .unwrap_or(align_up(size_of_headers, section_alignment));

        Ok(PeLayout {
            pe_offset,
            size_of_headers,
            size_of_image,
            entry_point: normalized.entry_point(),
            sections,
            overlay_offset,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.to_bytes_with_config(PeSerializationConfig::default())
    }

    pub fn to_bytes_with_config(&self, config: PeSerializationConfig) -> Result<Vec<u8>, Error> {
        let materialized_size = self.materialized_size();
        if let Some(max_materialized_size) = config.size_limits.max_materialized_size {
            if materialized_size > max_materialized_size {
                return Err(Error::layout(format!(
                    "materialized PE size {materialized_size} exceeds configured maximum size {max_materialized_size}"
                )));
            }
        }

        let mut normalized = self.clone();
        normalized.ensure_coherent_architecture();
        if normalized.sections.is_empty() {
            normalized
                .sections
                .push(PeSection::new(b".text", 0x1000, vec![0xc3], 0x6000_0020));
        }
        if normalized.entry_section_index().is_none() {
            let fallback = normalized.sections[0].virtual_address;
            normalized.set_entry_point(fallback);
        }

        let layout = normalized.layout()?;
        let declared_optional_size = normalized.declared_optional_header_size as usize;
        let optional_size = declared_optional_size.max(normalized.canonical_optional_header_size());
        let pe_offset = layout.pe_offset as usize;
        let file_alignment = normalized.file_alignment().max(1);
        let predicted_size = predicted_serialized_size(
            &normalized,
            &layout,
            optional_size,
            pe_offset,
            file_alignment,
        )?;
        if let Some(max_output_size) = config.size_limits.max_serialized_size {
            if predicted_size > max_output_size {
                return Err(Error::layout(format!(
                    "serialized PE size {predicted_size} exceeds configured maximum size {max_output_size}"
                )));
            }
        }

        let mut output = normalized.dos_stub.clone();
        output.resize(pe_offset.max(DOS_HEADER_LEN), 0);
        output[0..2].copy_from_slice(&DOS_MAGIC);
        write_u32_into(&mut output, 0x3c, layout.pe_offset);

        output.extend_from_slice(&PE_MAGIC);
        write_u16(&mut output, normalized.machine);
        write_u16(&mut output, normalized.sections.len() as u16);
        write_u32(&mut output, normalized.time_date_stamp);
        write_u32(&mut output, normalized.pointer_to_symbol_table);
        write_u32(&mut output, normalized.number_of_symbols);
        write_u16(&mut output, optional_size as u16);
        write_u16(&mut output, normalized.characteristics);

        let mut optional_header = normalized.optional_header.clone();
        optional_header.resize(optional_size, 0);
        normalized.patch_optional_header(&layout, &mut optional_header);
        output.extend_from_slice(&optional_header);

        for (section, layout_section) in normalized.sections.iter().zip(&layout.sections) {
            output.extend_from_slice(&section.name);
            write_u32(&mut output, layout_section.virtual_size);
            write_u32(&mut output, layout_section.virtual_address);
            write_u32(&mut output, layout_section.size_of_raw_data);
            write_u32(&mut output, layout_section.pointer_to_raw_data);
            write_u32(&mut output, layout_section.pointer_to_relocations);
            write_u32(&mut output, section.pointer_to_linenumbers);
            write_u16(&mut output, section.number_of_relocations);
            write_u16(&mut output, section.number_of_linenumbers);
            write_u32(&mut output, section.characteristics);
        }

        output.resize(layout.size_of_headers as usize, 0);

        for (section, layout_section) in normalized.sections.iter().zip(&layout.sections) {
            if layout_section.pointer_to_raw_data == 0 || section.raw_data.is_empty() {
                continue;
            }
            output.resize(layout_section.pointer_to_raw_data as usize, 0);
            output.extend_from_slice(&section.raw_data);
            let aligned = align_up(output.len() as u32, file_alignment) as usize;
            output.resize(aligned, 0);
        }

        output.resize(layout.overlay_offset as usize, 0);
        output.extend_from_slice(&normalized.overlay);
        Ok(output)
    }

    fn patch_optional_header(&self, layout: &PeLayout, optional_header: &mut [u8]) {
        let optional_magic = self.expected_optional_magic();
        write_u16_into(optional_header, 0x00, optional_magic);
        write_u32_into(optional_header, 0x10, self.entry_point());
        write_u32_into(optional_header, 0x20, self.section_alignment().max(1));
        write_u32_into(optional_header, 0x24, self.file_alignment().max(1));
        write_u32_into(optional_header, 0x38, layout.size_of_image);
        write_u32_into(optional_header, 0x3c, layout.size_of_headers);
        write_u32_into(
            optional_header,
            number_of_rva_and_sizes_offset(optional_magic),
            self.data_directories.len() as u32,
        );
        let table_offset = data_directories_offset(optional_magic);
        for (index, directory) in self.data_directories.iter().enumerate() {
            let entry_offset = table_offset + index * 8;
            write_u32_into(optional_header, entry_offset, directory.virtual_address);
            write_u32_into(optional_header, entry_offset + 4, directory.size);
        }
    }

    fn ensure_optional_field(&mut self, size: usize) {
        let canonical = self.canonical_optional_header_size();
        if self.optional_header.len() < size.max(canonical) {
            self.optional_header.resize(size.max(canonical), 0);
        }
    }

    fn ensure_optional_field_with_budget(
        &mut self,
        size: usize,
        budget: &mut PeSizeBudget,
    ) -> Result<(), Error> {
        let canonical = self.canonical_optional_header_size();
        let required_len = size.max(canonical);
        if self.optional_header.len() < required_len {
            budget.try_resize_delta(self.optional_header.len(), required_len)?;
            self.optional_header.resize(required_len, 0);
        }
        Ok(())
    }

    fn read_optional_u32(&self, offset: usize) -> Option<u32> {
        self.optional_header
            .get(offset..offset + 4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn minimum_optional_header_size(&self) -> usize {
        optional_header_size_for_data_directories(
            self.expected_optional_magic(),
            self.data_directories.len(),
        )
    }
}

fn predicted_serialized_size(
    input: &PeInput,
    layout: &PeLayout,
    optional_size: usize,
    pe_offset: usize,
    file_alignment: u32,
) -> Result<usize, Error> {
    let section_table_size = input
        .sections
        .len()
        .checked_mul(SECTION_HEADER_LEN)
        .ok_or_else(|| Error::layout("section table size overflows"))?;
    let mut output_len = input.dos_stub.len().max(pe_offset.max(DOS_HEADER_LEN));
    output_len = output_len
        .checked_add(4 + 20)
        .and_then(|len| len.checked_add(optional_size))
        .and_then(|len| len.checked_add(section_table_size))
        .ok_or_else(|| Error::layout("serialized PE header size overflows"))?;
    output_len = output_len.max(layout.size_of_headers as usize);

    for (section, layout_section) in input.sections.iter().zip(&layout.sections) {
        if layout_section.pointer_to_raw_data == 0 || section.raw_data.is_empty() {
            continue;
        }

        output_len = output_len.max(layout_section.pointer_to_raw_data as usize);
        output_len = output_len
            .checked_add(section.raw_data.len())
            .ok_or_else(|| Error::layout("serialized PE section data size overflows"))?;
        output_len = align_up_usize(output_len, file_alignment)?;
    }

    output_len = output_len.max(layout.overlay_offset as usize);
    output_len = output_len
        .checked_add(input.overlay.len())
        .ok_or_else(|| Error::layout("serialized PE overlay size overflows"))?;
    Ok(output_len)
}

fn align_up_usize(value: usize, alignment: u32) -> Result<usize, Error> {
    let value = u32::try_from(value)
        .map_err(|_| Error::layout("serialized PE size exceeds 32-bit layout bounds"))?;
    Ok(align_up(value, alignment.max(1)) as usize)
}

pub struct PeSummary<'a>(&'a PeInput);

impl fmt::Display for PeSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let input = self.0;
        let layout = input.layout().ok();
        writeln!(
            f,
            "machine=0x{:04x} optional_magic=0x{:03x} declared_optional=0x{:x} sections={} overlay={}",
            input.machine,
            input.optional_magic(),
            input.declared_optional_header_size,
            input.sections.len(),
            input.overlay.len()
        )?;
        writeln!(
            f,
            "entry_point=0x{:08x} section_alignment=0x{:x} file_alignment=0x{:x}",
            input.entry_point(),
            input.section_alignment(),
            input.file_alignment()
        )?;
        match &layout {
            Some(layout) if !input.overlay.is_empty() => {
                writeln!(
                    f,
                    "overlay offset=0x{:08x} size=0x{:x}",
                    layout.overlay_offset,
                    input.overlay.len()
                )?;
            }
            _ if !input.overlay.is_empty() => {
                writeln!(f, "overlay size=0x{:x}", input.overlay.len())?;
            }
            _ => {
                writeln!(f, "overlay none")?;
            }
        }
        match input.export_directory.as_ref() {
            Some(export) => {
                writeln!(
                    f,
                    "export_directory name={} ordinal_base={} addresses={} names={} eat_rva=0x{:08x} name_ptr_rva=0x{:08x} ordinal_rva=0x{:08x}",
                    export.name.as_deref().unwrap_or("<unresolved>"),
                    export.ordinal_base,
                    export.address_table_entries,
                    export.number_of_name_pointers,
                    export.export_address_table_rva,
                    export.name_pointer_rva,
                    export.ordinal_table_rva
                )?;
            }
            None => {
                writeln!(f, "export_directory none")?;
            }
        }
        match input.resource_directory.as_ref() {
            Some(resource) => {
                let stats = resource_directory_stats(resource);
                writeln!(
                    f,
                    "resource_directory dirs={} entries={} data_entries={} depth={} root_named={} root_ids={}",
                    stats.directories,
                    stats.entries,
                    stats.data_entries,
                    stats.max_depth,
                    resource.header.number_of_named_entries,
                    resource.header.number_of_id_entries
                )?;
            }
            None => {
                writeln!(f, "resource_directory none")?;
            }
        }
        for (index, section) in input.sections.iter().enumerate() {
            let line = if let Some(layout) = &layout {
                let placed = &layout.sections[index];
                format!(
                    "#{index} {} va=0x{:08x} vsz=0x{:x} raw=0x{:08x}+0x{:x} reloc=0x{:08x}",
                    section.name_string(),
                    placed.virtual_address,
                    placed.virtual_size,
                    placed.pointer_to_raw_data,
                    placed.size_of_raw_data,
                    placed.pointer_to_relocations
                )
            } else {
                format!(
                    "#{index} {} va=0x{:08x} vsz=0x{:x} raw=0x{:08x}+0x{:x} present=0x{:x} reloc=0x{:08x}",
                    section.name_string(),
                    section.virtual_address,
                    section.virtual_size,
                    section.header_pointer_to_raw_data(),
                    section.header_size_of_raw_data(),
                    section.size_of_raw_data(),
                    section.pointer_to_relocations
                )
            };
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ResourceDirectoryStats {
    directories: usize,
    entries: usize,
    data_entries: usize,
    max_depth: usize,
}

fn resource_directory_stats(root: &ParsedResourceDirectory) -> ResourceDirectoryStats {
    fn visit(
        directory: &ParsedResourceDirectory,
        depth: usize,
        stats: &mut ResourceDirectoryStats,
    ) {
        stats.directories += 1;
        stats.entries += directory.entries.len();
        stats.max_depth = stats.max_depth.max(depth);

        for entry in &directory.entries {
            match &entry.target {
                ResourceEntryTarget::Directory(child) => visit(child, depth + 1, stats),
                ResourceEntryTarget::Data(_) => stats.data_entries += 1,
            }
        }
    }

    let mut stats = ResourceDirectoryStats::default();
    visit(root, 1, &mut stats);
    stats
}
