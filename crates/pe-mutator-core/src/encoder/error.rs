use crate::error::Error;
use std::{
    env,
    fmt::{Debug, Display},
    fs::{OpenOptions, create_dir_all},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

const ICED_ERROR_LOG_PATH_ENV: &str = "PE_MUTATOR_ICED_ERROR_LOG";

static ICED_ERROR_LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn iced_error(err: iced_x86::IcedError) -> Error {
    Error::encoding(format!("iced-x86 lowering failed: {err}"))
}

pub fn set_iced_error_log_path(path: impl Into<PathBuf>) {
    if let Ok(mut slot) = ICED_ERROR_LOG_PATH.lock() {
        *slot = Some(path.into());
    }
}

pub fn clear_iced_error_log_path() {
    if let Ok(mut slot) = ICED_ERROR_LOG_PATH.lock() {
        *slot = None;
    }
}

pub fn iced_error_log_env_var() -> &'static str {
    ICED_ERROR_LOG_PATH_ENV
}

pub fn iced_error_with_context<I, E>(arch: &str, stage: &str, insn: &I, ip: u64, err: E) -> Error
where
    I: Debug,
    E: Display,
{
    let message = format!("iced-x86 {stage} failed for {arch} insn={insn:?} ip=0x{ip:x}: {err}");
    log_iced_error_line(&message);
    Error::encoding(message)
}

fn log_iced_error_line(message: &str) {
    let Some(path) = configured_iced_error_log_path() else {
        return;
    };

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        let _ = create_dir_all(parent);
    }

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{message}");
    }
}

fn configured_iced_error_log_path() -> Option<PathBuf> {
    ICED_ERROR_LOG_PATH
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .or_else(env_iced_error_log_path)
}

fn env_iced_error_log_path() -> Option<PathBuf> {
    env::var_os(ICED_ERROR_LOG_PATH_ENV).map(PathBuf::from)
}

pub fn iced_error_log_path() -> Option<PathBuf> {
    configured_iced_error_log_path()
}

pub fn log_iced_errors_to_file(path: impl AsRef<Path>) {
    set_iced_error_log_path(path.as_ref().to_path_buf());
}
