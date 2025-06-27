//! Raw / caller-supplied buffer helpers for the `SlotHashes` sysvar.
//!
//! This sub-module exposes lightweight functions that let a program copy
//! `SlotHashes` data directly into an arbitrary buffer **without** constructing
//! a `SlotHashes<T>` view. Use these when you only need a byte snapshot or
//! when including the sysvar account is infeasible.
#![allow(clippy::inline_always)]

use super::{ENTRY_SIZE, MAX_ENTRIES, MAX_SIZE, NUM_ENTRIES_SIZE, ProgramError, SLOTHASHES_ID, read_entry_count_from_bytes};

pub const ERR_RAW_BAD_SHAPE: u32 = 0x10; // buffer not 8 + n*40
pub const ERR_RAW_ENTRY_OVERFLOW: u32 = 0x11; // >512 entries possible / declared
pub const ERR_RAW_BAD_OFFSET: u32 = 0x12; // offset not aligned or past end
pub const ERR_RAW_LEN_TOO_SMALL: u32 = 0x13; // buffer shorter than declared length

/// Validates that a buffer is properly sized for `SlotHashes` data.
///
/// Checks that the buffer length is 8 + (N × 40) for some N ≤ 512.
/// Unlike the `SlotHashes` constructor, this function does not require
/// the buffer to be exactly 20,488 bytes.
#[inline(always)]
pub(crate) fn validate_buffer_size(buffer_len: usize) -> Result<(), ProgramError> {
    // Must have space for 8-byte header
    if buffer_len < NUM_ENTRIES_SIZE {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Calculate how many entries can fit
    let data_len = buffer_len - NUM_ENTRIES_SIZE;
    if data_len % ENTRY_SIZE != 0 {
        return Err(ProgramError::Custom(ERR_RAW_BAD_SHAPE));
    }

    let max_entries = data_len / ENTRY_SIZE;
    if max_entries > MAX_ENTRIES {
        return Err(ProgramError::Custom(ERR_RAW_ENTRY_OVERFLOW));
    }

    Ok(())
}

/// Validates offset parameters for fetching `SlotHashes` data.
///
/// * `offset` – Byte offset within the `SlotHashes` sysvar data.
/// * `buffer_len` – Length of the destination buffer.
#[inline(always)]
pub fn validate_fetch_offset(offset: usize, buffer_len: usize) -> Result<(), ProgramError> {
    if offset >= MAX_SIZE {
        return Err(ProgramError::Custom(ERR_RAW_BAD_OFFSET));
    }
    if offset != 0 && (offset < NUM_ENTRIES_SIZE || (offset - NUM_ENTRIES_SIZE) % ENTRY_SIZE != 0) {
        return Err(ProgramError::Custom(ERR_RAW_BAD_OFFSET));
    }
    if offset.saturating_add(buffer_len) > MAX_SIZE {
        return Err(ProgramError::Custom(ERR_RAW_BAD_OFFSET));
    }

    Ok(())
}

/// Copies `SlotHashes` sysvar bytes into `buffer`, performing validation.
///
/// Returns the number of entries present in the sysvar.
#[inline(always)]
pub fn fetch_into(buffer: &mut [u8], offset: usize) -> Result<usize, ProgramError> {
    if buffer.len() != MAX_SIZE {
        validate_buffer_size(buffer.len())?;
    }

    validate_fetch_offset(offset, buffer.len())?;

    fetch_into_unchecked(buffer, offset)?;

    let num_entries = read_entry_count_from_bytes(buffer).unwrap_or(0);

    // Reject oversized entry counts to prevent surprises.
    if num_entries > MAX_ENTRIES {
        return Err(ProgramError::Custom(ERR_RAW_ENTRY_OVERFLOW));
    }

    let required_len = NUM_ENTRIES_SIZE + num_entries * ENTRY_SIZE;
    if buffer.len() < required_len {
        return Err(ProgramError::Custom(ERR_RAW_LEN_TOO_SMALL));
    }

    Ok(num_entries)
}

/// Copies `SlotHashes` sysvar bytes into `buffer` **without** validation.
///
/// The caller is responsible for ensuring that:
/// 1. `buffer` is large enough for the requested `offset`+`buffer.len()` range and
///    properly laid out (see `validate_buffer_size` and `validate_fetch_offset`).
/// 2. The memory behind `buffer` is writable for its full length.
///
/// # Safety
/// Internally this function performs an unchecked Solana syscall that writes
/// raw bytes into the provided pointer. That call is wrapped in an `unsafe`
/// block with the guarantees listed above.
#[inline(always)]
pub fn fetch_into_unchecked(buffer: &mut [u8], offset: usize) -> Result<(), ProgramError> {
    // SAFETY: `buffer.as_mut_ptr()` is valid for `buffer.len()` bytes and
    // writable for the duration of the call. We rely on the caller to have
    // ensured that `offset + buffer.len()` does not exceed the real sysvar
    // size (`MAX_SIZE`).
    unsafe {
        crate::sysvars::get_sysvar_unchecked(
            buffer.as_mut_ptr(),
            &SLOTHASHES_ID,
            offset,
            buffer.len(),
        )
    }?;

    Ok(())
}
