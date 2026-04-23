pub fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment <= 1 {
        value
    } else {
        let remainder = value % alignment;
        if remainder == 0 {
            value
        } else {
            value.saturating_add(alignment - remainder)
        }
    }
}
