use std::{cell::RefCell, ffi::c_char, ptr, slice};

pub use pe_mutator_core::core::{SimpleRng, DEFAULT_SEED};
use pe_mutator_core::error::Error as CoreError;
use pe_mutator_core::pe::PeInput;

pub mod mutator;

pub use mutator::{
    PEMutator, PeMutateCategoryBits, PeMutateCfg, PeMutateMutationBits, PE_MUTATE_CATEGORY_ALL,
    PE_MUTATE_CATEGORY_ARCHITECTURE, PE_MUTATE_CATEGORY_ASSEMBLY,
    PE_MUTATE_CATEGORY_DATA_DIRECTORIES, PE_MUTATE_CATEGORY_HEADERS, PE_MUTATE_CATEGORY_NONE,
    PE_MUTATE_CATEGORY_OVERLAY, PE_MUTATE_CATEGORY_SECTIONS, PE_MUTATE_MUTATION_ALL,
    PE_MUTATE_MUTATION_ARCHITECTURE, PE_MUTATE_MUTATION_DATA_DIRECTORY_ENTRY,
    PE_MUTATE_MUTATION_ENTRY_POINT, PE_MUTATE_MUTATION_EXECUTABLE_CHUNK_ASSEMBLY,
    PE_MUTATE_MUTATION_EXPORT_DIRECTORY, PE_MUTATE_MUTATION_NONE, PE_MUTATE_MUTATION_OVERLAY,
    PE_MUTATE_MUTATION_RESOURCE_DIRECTORY, PE_MUTATE_MUTATION_SECTION_BODY,
    PE_MUTATE_MUTATION_SECTION_COUNT, PE_MUTATE_MUTATION_SECTION_HEADER,
};

thread_local! {
    static LAST_ERROR_MESSAGE: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeMutateStatus {
    Ok = 0,
    NullPointer = 1,
    ParseError = 2,
    BufferTooSmall = 3,
    InternalError = 4,
}

fn clear_last_error_message() {
    LAST_ERROR_MESSAGE.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

fn set_last_error_message(message: impl Into<String>) {
    let bytes = message.into().into_bytes();
    LAST_ERROR_MESSAGE.with(|slot| {
        *slot.borrow_mut() = Some(bytes);
    });
}

fn set_core_error_message(stage: &str, err: &CoreError) {
    set_last_error_message(format!(
        "{stage} failed (kind={:?}): {}",
        err.kind(),
        err.message()
    ));
}

unsafe fn write_last_error_message(
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> PeMutateStatus {
    if out_len.is_null() {
        return PeMutateStatus::NullPointer;
    }
    if out_cap != 0 && out_buf.is_null() {
        return PeMutateStatus::NullPointer;
    }

    let bytes = LAST_ERROR_MESSAGE
        .with(|slot| slot.borrow().as_ref().cloned())
        .unwrap_or_default();
    let required_len = bytes.len() + 1;

    unsafe { ptr::write(out_len, required_len) };
    if required_len > out_cap {
        return PeMutateStatus::BufferTooSmall;
    }

    if !bytes.is_empty() {
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf.cast::<u8>(), bytes.len()) };
    }
    if out_cap != 0 {
        unsafe { ptr::write(out_buf.cast::<u8>().add(bytes.len()), 0) };
    }

    PeMutateStatus::Ok
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_mutate_bytes(
    in_buf: *const u8,
    in_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    cfg: *const PeMutateCfg,
) -> PeMutateStatus {
    clear_last_error_message();

    if out_len.is_null() {
        set_last_error_message("out_len must not be null");
        return PeMutateStatus::NullPointer;
    }
    if in_len != 0 && in_buf.is_null() {
        set_last_error_message("in_buf must not be null when in_len is non-zero");
        return PeMutateStatus::NullPointer;
    }
    if out_cap != 0 && out_buf.is_null() {
        set_last_error_message("out_buf must not be null when out_cap is non-zero");
        return PeMutateStatus::NullPointer;
    }

    let in_slice = unsafe { slice::from_raw_parts(in_buf, in_len) };
    let cfg = if cfg.is_null() {
        PeMutateCfg::default()
    } else {
        unsafe { *cfg }
    };

    let mut mutator = PEMutator::with_config(cfg);
    let mut input = match PeInput::parse(in_slice) {
        Ok(input) => input,
        Err(err) => {
            set_core_error_message("PeInput::parse", &err);
            return PeMutateStatus::ParseError;
        }
    };
    if let Err(err) = mutator.mutate_parsed(&mut input) {
        set_core_error_message("PEMutator::mutate_parsed", &err);
        return PeMutateStatus::InternalError;
    }
    let out_bytes = match input.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            set_core_error_message("PeInput::to_bytes", &err);
            return PeMutateStatus::InternalError;
        }
    };

    unsafe { ptr::write(out_len, out_bytes.len()) };
    if out_bytes.len() > out_cap {
        set_last_error_message(format!(
            "output buffer too small: need {} bytes, have {}",
            out_bytes.len(),
            out_cap
        ));
        return PeMutateStatus::BufferTooSmall;
    }

    if !out_bytes.is_empty() {
        unsafe { ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_buf, out_bytes.len()) };
    }

    PeMutateStatus::Ok
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_last_error_message(
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> PeMutateStatus {
    unsafe { write_last_error_message(out_buf, out_cap, out_len) }
}
