use crate::error::Error;

pub struct ReadCStringResult<'a> {
    pub bytes: &'a [u8],
    pub terminated: bool,
}

pub fn read_c_string_bytes(
    bytes: &[u8],
    offset: usize,
    max_len: usize,
) -> Option<ReadCStringResult<'_>> {
    let tail = bytes.get(offset..)?;
    let limit = tail.len().min(max_len);
    let window = &tail[..limit];

    match window.iter().position(|b| *b == 0) {
        Some(nul) => Some(ReadCStringResult {
            bytes: &window[..nul],
            terminated: true,
        }),
        None => Some(ReadCStringResult {
            bytes: window,
            terminated: false,
        }),
    }
}

pub fn read_c_string_lossy(bytes: &[u8], offset: usize, max_len: usize) -> Option<(String, bool)> {
    let result = read_c_string_bytes(bytes, offset, max_len)?;
    Some((
        String::from_utf8_lossy(result.bytes).into_owned(),
        result.terminated,
    ))
}

pub fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| Error::illegal_argument("u16 field is out of bounds"))?;
    Ok(u16::from_le_bytes(slice.try_into().unwrap()))
}

pub fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| Error::illegal_argument("u32 field is out of bounds"))?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

pub fn write_u16(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

pub fn write_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

pub fn write_u16_into(buffer: &mut [u8], offset: usize, value: u16) {
    if let Some(slot) = buffer.get_mut(offset..offset + 2) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

pub fn write_u32_into(buffer: &mut [u8], offset: usize, value: u32) {
    if let Some(slot) = buffer.get_mut(offset..offset + 4) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}
