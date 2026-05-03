use crate::io::write_u32_into;

pub const DOS_MAGIC: [u8; 2] = *b"MZ";
pub const DEFAULT_PE_OFFSET: usize = 0x80;

pub fn default_dos_stub() -> Vec<u8> {
    let mut stub = vec![0_u8; DEFAULT_PE_OFFSET];
    stub[0..2].copy_from_slice(&DOS_MAGIC);
    write_u32_into(&mut stub, 0x3c, DEFAULT_PE_OFFSET as u32);
    stub
}
