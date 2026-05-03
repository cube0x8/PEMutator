use pe_mutator_core::io::{read_u32, write_u16_into, write_u32_into};
use pe_mutator_core::pe::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, OPTIONAL_MAGIC_PE32_PLUS, PeInput, PeSection,
};

const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
const IMAGE_EXPORT_DIRECTORY_LEN: usize = 40;

fn number_of_rva_and_sizes_offset(optional_magic: u16) -> usize {
    match optional_magic {
        OPTIONAL_MAGIC_PE32_PLUS => 0x6c,
        _ => 0x5c,
    }
}

fn data_directories_offset(optional_magic: u16) -> usize {
    match optional_magic {
        OPTIONAL_MAGIC_PE32_PLUS => 0x70,
        _ => 0x60,
    }
}

#[test]
fn templates_initialize_data_directories_for_pe32_and_pe32_plus() {
    let pe32 = PeInput::template(IMAGE_FILE_MACHINE_I386);
    assert_eq!(pe32.data_directories.len(), 16);
    assert_eq!(
        u32::from_le_bytes(
            pe32.optional_header[number_of_rva_and_sizes_offset(pe32.optional_magic())
                ..number_of_rva_and_sizes_offset(pe32.optional_magic()) + 4]
                .try_into()
                .unwrap()
        ),
        16
    );

    let pe32_plus = PeInput::template(IMAGE_FILE_MACHINE_AMD64);
    assert_eq!(pe32_plus.data_directories.len(), 16);
    assert_eq!(
        u32::from_le_bytes(
            pe32_plus.optional_header[number_of_rva_and_sizes_offset(pe32_plus.optional_magic())
                ..number_of_rva_and_sizes_offset(pe32_plus.optional_magic()) + 4]
                .try_into()
                .unwrap()
        ),
        16
    );
    assert_eq!(data_directories_offset(pe32_plus.optional_magic()), 0x70);
}

#[test]
fn parse_and_serialize_roundtrip_data_directories() {
    let mut input = PeInput::template(IMAGE_FILE_MACHINE_AMD64);
    input.data_directories[1].virtual_address = 0x1234;
    input.data_directories[1].size = 0x56;
    input.data_directories[15].virtual_address = 0x2000;
    input.data_directories[15].size = 0x80;

    let reparsed = PeInput::parse(&input.to_bytes().unwrap()).unwrap();

    assert_eq!(reparsed.data_directories, input.data_directories);
}

#[test]
fn parse_export_directory_from_section_bytes() {
    let mut input = PeInput::template(IMAGE_FILE_MACHINE_I386);
    let mut edata = vec![0_u8; 0x80];
    write_u32_into(&mut edata, 0x00, 0x1122_3344);
    write_u32_into(&mut edata, 0x04, 0x5566_7788);
    write_u16_into(&mut edata, 0x08, 1);
    write_u16_into(&mut edata, 0x0a, 7);
    write_u32_into(&mut edata, 0x0c, 0x3040);
    write_u32_into(&mut edata, 0x10, 5);
    write_u32_into(&mut edata, 0x14, 3);
    write_u32_into(&mut edata, 0x18, 2);
    write_u32_into(&mut edata, 0x1c, 0x3050);
    write_u32_into(&mut edata, 0x20, 0x3060);
    write_u32_into(&mut edata, 0x24, 0x3070);
    edata[0x40..0x4b].copy_from_slice(b"sample.dll\0");

    input
        .sections
        .push(PeSection::new(b".edata", 0x3000, edata, 0x4000_0040));
    input.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address = 0x3000;
    input.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].size = IMAGE_EXPORT_DIRECTORY_LEN as u32;

    let reparsed = PeInput::parse(&input.to_bytes().unwrap()).unwrap();
    let export = reparsed
        .export_directory
        .expect("expected parsed export directory");

    assert_eq!(export.characteristics, 0x1122_3344);
    assert_eq!(export.time_date_stamp, 0x5566_7788);
    assert_eq!(export.major_version, 1);
    assert_eq!(export.minor_version, 7);
    assert_eq!(export.name_rva, 0x3040);
    assert_eq!(export.name.as_deref(), Some("sample.dll"));
    assert_eq!(export.ordinal_base, 5);
    assert_eq!(export.address_table_entries, 3);
    assert_eq!(export.number_of_name_pointers, 2);
    assert_eq!(export.export_address_table_rva, 0x3050);
    assert_eq!(export.name_pointer_rva, 0x3060);
    assert_eq!(export.ordinal_table_rva, 0x3070);
}

#[test]
fn parse_export_directory_even_if_declared_size_is_too_small() {
    let mut input = PeInput::template(IMAGE_FILE_MACHINE_I386);
    let mut edata = vec![0_u8; 0x80];
    write_u32_into(&mut edata, 0x00, 0x1122_3344);
    write_u32_into(&mut edata, 0x04, 0x5566_7788);
    write_u16_into(&mut edata, 0x08, 1);
    write_u16_into(&mut edata, 0x0a, 7);
    write_u32_into(&mut edata, 0x0c, 0x3040);
    write_u32_into(&mut edata, 0x10, 5);
    write_u32_into(&mut edata, 0x14, 3);
    write_u32_into(&mut edata, 0x18, 2);
    write_u32_into(&mut edata, 0x1c, 0x3050);
    write_u32_into(&mut edata, 0x20, 0x3060);
    write_u32_into(&mut edata, 0x24, 0x3070);
    edata[0x40..0x4b].copy_from_slice(b"sample.dll\0");

    input
        .sections
        .push(PeSection::new(b".edata", 0x3000, edata, 0x4000_0040));
    input.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address = 0x3000;
    input.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].size = 4;

    let reparsed = PeInput::parse(&input.to_bytes().unwrap()).unwrap();
    let export = reparsed
        .export_directory
        .expect("expected parsed export directory despite undersized data directory");

    assert_eq!(export.name.as_deref(), Some("sample.dll"));
    assert_eq!(export.ordinal_table_rva, 0x3070);
}

#[test]
fn summary_includes_overlay_export_and_resource_details() {
    let mut input = PeInput::template(IMAGE_FILE_MACHINE_I386);

    let mut edata = vec![0_u8; 0x80];
    write_u32_into(&mut edata, 0x00, 0x1122_3344);
    write_u32_into(&mut edata, 0x04, 0x5566_7788);
    write_u16_into(&mut edata, 0x08, 1);
    write_u16_into(&mut edata, 0x0a, 7);
    write_u32_into(&mut edata, 0x0c, 0x3040);
    write_u32_into(&mut edata, 0x10, 5);
    write_u32_into(&mut edata, 0x14, 3);
    write_u32_into(&mut edata, 0x18, 2);
    write_u32_into(&mut edata, 0x1c, 0x3050);
    write_u32_into(&mut edata, 0x20, 0x3060);
    write_u32_into(&mut edata, 0x24, 0x3070);
    edata[0x40..0x4b].copy_from_slice(b"sample.dll\0");

    let mut rsrc = vec![0_u8; 0x80];
    write_u16_into(&mut rsrc, 0x0c, 0);
    write_u16_into(&mut rsrc, 0x0e, 1);
    write_u32_into(&mut rsrc, 0x10, 16);
    write_u32_into(&mut rsrc, 0x14, 0x18);
    write_u32_into(&mut rsrc, 0x18, 0x3040);
    write_u32_into(&mut rsrc, 0x1c, 4);
    write_u32_into(&mut rsrc, 0x20, 0);
    write_u32_into(&mut rsrc, 0x24, 0);
    rsrc[0x40..0x44].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    input
        .sections
        .push(PeSection::new(b".edata", 0x3000, edata, 0x4000_0040));
    input
        .sections
        .push(PeSection::new(b".rsrc", 0x4000, rsrc, 0x4000_0040));
    input.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address = 0x3000;
    input.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].size = IMAGE_EXPORT_DIRECTORY_LEN as u32;
    input.data_directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address = 0x4000;
    input.data_directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].size = 0x44;
    input.overlay = vec![0xaa, 0xbb, 0xcc, 0xdd];

    let reparsed = PeInput::parse(&input.to_bytes().unwrap()).unwrap();
    let summary = reparsed.summary().to_string();

    assert!(summary.contains("overlay offset=0x"));
    assert!(summary.contains("size=0x4"));
    assert!(summary.contains("export_directory name=sample.dll"));
    assert!(summary.contains("ordinal_base=5"));
    assert!(summary.contains("addresses=3"));
    assert!(summary.contains("names=2"));
    assert!(summary.contains("resource_directory dirs=1 entries=1 data_entries=1 depth=1"));
    assert!(summary.contains("root_named=0 root_ids=1"));
}

#[test]
fn parse_and_serialize_preserves_section_declared_beyond_eof() {
    let mut input = PeInput::template(IMAGE_FILE_MACHINE_I386);
    input.sections.truncate(1);
    input.sections[0].declared_pointer_to_raw_data = 0x400;
    input.sections[0].declared_size_of_raw_data = 0x200;
    input.sections[0].raw_data = vec![0xaa, 0xbb, 0xcc];
    input.sections[0].virtual_size = 0x200;
    input.overlay.clear();

    let mut bytes = input.to_bytes().unwrap();
    bytes.truncate(0x401);

    let reparsed = PeInput::parse(&bytes).unwrap();
    let section = &reparsed.sections[0];

    assert_eq!(section.header_pointer_to_raw_data(), 0x400);
    assert_eq!(section.header_size_of_raw_data(), 0x200);
    assert_eq!(section.raw_data, vec![0xaa]);

    let reserialized = reparsed.to_bytes().unwrap();
    assert_eq!(
        read_u32(&reserialized, 0x80 + 4 + 20 + 0xe0 + 20).unwrap(),
        0x400
    );
    assert_eq!(
        read_u32(&reserialized, 0x80 + 4 + 20 + 0xe0 + 16).unwrap(),
        0x200
    );
    assert_eq!(reserialized.len(), 0x401);
}
