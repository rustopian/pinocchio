//! Efficient, zero-copy access to the SlotHashes sysvar.
//!
//! This module provides a way to access the SlotHashes sysvar data
//! directly from account data without requiring full deserialization or
//! relying on potentially inefficient syscalls for individual entries.
//! No impl_sysvar_get! since the data is too huge.

use crate::{
    account_info::{AccountInfo, Ref},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::clock::Slot,
};
use core::{mem, ops::Deref};

/// SysvarS1otHashes111111111111111111111111111
pub const SLOTHASHES_ID: Pubkey = [
    6, 167, 213, 23, 25, 47, 10, 175, 198, 242, 101, 227, 251, 119, 204, 122, 218, 130, 197, 41,
    208, 190, 59, 19, 110, 45, 0, 85, 32, 0, 0, 0,
];
pub const MAX_ENTRIES: usize = 512;
pub const HASH_BYTES: usize = 32;

/// Sysvar data is:
/// len    (8 bytes): little-endian entry count (≤ 512)
/// entries(len × 40 bytes):    consecutive `(u64 slot, [u8;32] hash)` pairs
const NUM_ENTRIES_SIZE: usize = mem::size_of::<u64>();
pub const SLOT_SIZE: usize = mem::size_of::<Slot>();
pub const ENTRY_SIZE: usize = SLOT_SIZE + HASH_BYTES;

/// A single entry in the `SlotHashes` sysvar.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(C)]
pub struct SlotHashEntry {
    /// The slot number.
    pub slot: Slot,
    /// The hash corresponding to the slot.
    pub hash: [u8; HASH_BYTES],
}

/// Provides zero-copy access to the data of the `SlotHashes` sysvar.
///
/// This struct can work with either a safely borrowed `Ref<'a, [u8]>` from an
/// `AccountInfo` (via `from_account_info`) or a raw `&'a [u8]` slice
/// (via the `new_unchecked` constructor).
pub struct SlotHashes<T> 
where 
    T: Deref<Target = [u8]>,
{
    data: T,
    len: usize, // TODO: check whether we can just assume total len
}

// Implementation for any T that Derefs to [u8]
impl<T> SlotHashes<T> 
where 
    T: Deref<Target = [u8]>,
{
    /// Creates a `SlotHashes` instance directly from a data container and entry count.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it does not check the validity of the data or count.
    /// The caller must ensure:
    /// 1. The underlying byte slice in `data` represents valid SlotHashes data
    ///    (length prefix + entries).
    /// 2. `len` is the correct number of entries (≤ MAX_ENTRIES), matching the prefix.
    /// 3. The data slice contains at least `NUM_ENTRIES_SIZE + len * ENTRY_SIZE` bytes.
    /// 4. If `T` is `&[u8]`, the caller must ensure borrow rules are upheld.
    /// 5. Alignment is correct.
    #[inline(always)]
    pub unsafe fn new_unchecked(data: T, len: usize) -> Self {
        SlotHashes { data, len }
    }

    /// Helper function to parse and validate SlotHashes sysvar data from a slice.
    /// Used by the checked `from_account_info` path, but not unchecked paths.
    /// Returns (number_of_entries, required_length) if valid.
    #[inline(always)]
    fn parse_and_validate_data(data: &[u8]) -> Result<(usize, usize), ProgramError> {
        if data.len() < NUM_ENTRIES_SIZE {
            // Check 3a: Data long enough for len prefix
            return Err(ProgramError::AccountDataTooSmall);
        }
        
        let len_bytes: [u8; NUM_ENTRIES_SIZE] = unsafe { data.get_unchecked(0..NUM_ENTRIES_SIZE) }
            .try_into()
            .unwrap();
        let num_entries = u64::from_le_bytes(len_bytes);
        let num_entries_usize = (num_entries as usize).min(MAX_ENTRIES);
        
        let required_len =
            NUM_ENTRIES_SIZE.saturating_add(num_entries_usize.saturating_mul(ENTRY_SIZE));

        if data.len() < required_len {
            // Check 3b: Data long enough for declared entries
            return Err(ProgramError::InvalidAccountData);
        }
        
        Ok((num_entries_usize, required_len))
    }

    /// Validates a byte slice as SlotHashes data and returns the entry count.
    ///
    /// This function checks that:
    /// - The data contains a valid length prefix
    /// - The data is sufficiently large to hold the indicated number of entries
    ///
    /// Returns `ProgramError::AccountDataTooSmall` if the data is too short.
    /// Returns `ProgramError::InvalidAccountData` if the data length is inconsistent.
    #[inline(always)]
    pub fn from_bytes(data: &[u8]) -> Result<usize, ProgramError> {
        let (num_entries, _) = Self::parse_and_validate_data(data)?;
        Ok(num_entries)
    }

    /// Gets the number of entries stored in the provided data slice.
    /// Performs validation checks and returns the entry count if valid.
    /// 
    /// Useful for testing or when only the entry count is needed.
    #[inline(always)]
    pub fn get_entry_count(data: &[u8]) -> Result<usize, ProgramError> {
        let (num_entries, _) = Self::parse_and_validate_data(data)?;
        Ok(num_entries)
    }

    /// Reads the entry count directly from the beginning of a byte slice **without validation**.
    ///
    /// This function caps the read count at `MAX_ENTRIES`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it performs no checks on the input slice.
    /// The caller **must** ensure that:
    /// 1. `data` contains at least `NUM_ENTRIES_SIZE` (8) bytes.
    /// 2. The first 8 bytes represent a valid `u64` in little-endian format.
    /// 3. Calling this function without ensuring the above may lead to panics
    ///    (out-of-bounds access) or incorrect results.
    ///
    /// This is intended for extreme performance scenarios where the data slice validity
    /// is guaranteed by external means.
    #[inline(always)]
    pub unsafe fn get_entry_count_unchecked(data: &[u8]) -> usize {
        // Unsafe access: assumes data has at least NUM_ENTRIES_SIZE bytes.
        let len_bytes: [u8; NUM_ENTRIES_SIZE] = data
            .get_unchecked(0..NUM_ENTRIES_SIZE)
            .try_into()
            .unwrap_unchecked();
        let num_entries = u64::from_le_bytes(len_bytes);
        (num_entries as usize).min(MAX_ENTRIES) // Cap at MAX_ENTRIES
    }

    /// Returns the number of `SlotHashEntry` items accessible.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if there are no entries.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Gets a reference to the `SlotHashEntry` at the specified index.
    ///
    /// Returns `None` if the index is out of bounds.
    /// The returned reference is tied to the lifetime of the borrow of `self`.
    #[inline(always)]
    pub fn get_entry(&self, index: usize) -> Option<&SlotHashEntry> {
        if index >= self.len {
            return None;
        }
        // Get slice using Deref on self.data
        let full_data_slice: &[u8] = &self.data;
        // Safety: Length check in constructor/new_unchecked ensures this offset is valid.
        let entries_data = unsafe { full_data_slice.get_unchecked(NUM_ENTRIES_SIZE..) };

        // Calculate offsets within the entries_data slice
        let start = index.checked_mul(ENTRY_SIZE)?;
        let end = start.checked_add(ENTRY_SIZE)?;

        // Safely slice the specific entry bytes from entries_data (lifetime 's)
        let entry_bytes = entries_data.get(start..end)?;

        // Zero-copy cast (lifetime 's)
        // Safety: Relies on constructor/new_unchecked checks, repr(C), and alignment.
        Some(unsafe { &*(entry_bytes.as_ptr() as *const SlotHashEntry) })
    }

    /// Gets a reference to the `SlotHashEntry` at the specified index without bounds checking.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it does not verify if the index is out of bounds.
    /// The caller must ensure that `index < self.len()`.
    ///
    /// This function is typically used in performance-critical code paths where
    /// the index has already been validated, such as within `binary_search_slot`.
    #[inline(always)]
    pub unsafe fn get_entry_unchecked(&self, index: usize) -> &SlotHashEntry {
        // Get slice using Deref on self.data
        let full_data_slice: &[u8] = &self.data;
        let entries_data = full_data_slice.get_unchecked(NUM_ENTRIES_SIZE..);
        
        let offset = index * ENTRY_SIZE;
        let entry_bytes = entries_data.get_unchecked(offset..(offset + ENTRY_SIZE));
        
        &*(entry_bytes.as_ptr() as *const SlotHashEntry)
    }

    /// Performs a binary search to find an entry with the given slot number.
    ///
    /// This uses a bounded interpolation search strategy that takes advantage of:
    /// 1. Slots are monotonically decreasing
    /// 2. Typical gap between slots is ~5% (used as a search heuristic)
    /// 3. Minimum gap between slots is 1
    ///
    /// When we find a slot at an index, we can calculate minimum bounds based on
    /// the minimum gap, and use typical gaps as a heuristic for probing.
    #[inline(always)]
    fn binary_search_slot(&self, target_slot: Slot) -> Option<usize> {
        let len = self.len;
        if len == 0 {
            return None;
        }
        let first_slot = unsafe { self.get_entry_unchecked(0).slot };
        if target_slot > first_slot {
            return None;
        }
        if target_slot == first_slot {
            return Some(0);
        }

        let mut low = 0;
        let mut high = len;

        while low < high {
            let delta_slots = first_slot.saturating_sub(target_slot);
            let estimated_index = ((delta_slots.saturating_mul(19)) / 20) as usize;
            let mid = estimated_index.clamp(low, high.saturating_sub(1));
            let entry_slot = unsafe { self.get_entry_unchecked(mid).slot };

            match entry_slot.cmp(&target_slot) {
                core::cmp::Ordering::Equal => return Some(mid),
                core::cmp::Ordering::Greater => {
                    let slot_diff = entry_slot - target_slot;
                    let max_possible_index = mid.saturating_add(slot_diff as usize);
                    low = mid + 1;
                    high = high.min(max_possible_index.saturating_add(1));
                }
                core::cmp::Ordering::Less => {
                    let slot_diff = target_slot - entry_slot;
                    let min_possible_index = mid.saturating_sub(slot_diff as usize);
                    high = mid;
                    low = low.max(min_possible_index);
                }
            }
            // Check if bounds crossed after update
            if low >= high {
                break;
            }
        }
        None // Not found
    }

    /// Performs a standard (unweighted) binary search to find an entry with the given slot number.
    ///
    /// Assumes entries are sorted by slot in descending order.
    /// Returns the index of the matching entry, or `None` if not found.
    #[inline(always)]
    fn binary_search_slot_midpoint(&self, target_slot: Slot) -> Option<usize> {
        if self.len == 0 {
            return None;
        }

        let mut low = 0;
        let mut high = self.len;

        while low < high {
            let mid = low + (high - low) / 2; // Standard midpoint calculation
            let entry_slot = unsafe { self.get_entry_unchecked(mid).slot };

            match entry_slot.cmp(&target_slot) {
                core::cmp::Ordering::Equal => return Some(mid),
                core::cmp::Ordering::Less => high = mid, // Target in lower half (higher slots)
                core::cmp::Ordering::Greater => low = mid + 1, // Target in upper half (lower slots)
            }
        }

        None // Not found
    }

    /// Finds the hash for a specific slot using binary search.
    ///
    /// Returns the hash if the slot is found, or `None` if not found.
    /// Assumes entries are sorted by slot in descending order.
    #[inline(always)]
    pub fn get_hash(&self, target_slot: Slot) -> Option<&[u8; HASH_BYTES]> {
        // Use the default interpolation search
        self.binary_search_slot(target_slot)
            .and_then(|idx| self.get_entry(idx))
            .map(|entry| &entry.hash)
    }

    /// Finds the position (index) of a specific slot using binary search.
    ///
    /// Returns the index if the slot is found, or `None` if not found.
    /// Assumes entries are sorted by slot in descending order.
    #[inline(always)]
    pub fn position(&self, target_slot: Slot) -> Option<usize> {
        // Use the default interpolation search
        self.binary_search_slot(target_slot)
    }

    /// Finds the hash for a specific slot using standard (unweighted) binary search.
    ///
    /// Returns the hash if the slot is found, or `None` if not found.
    /// Assumes entries are sorted by slot in descending order.
    #[inline(always)]
    pub fn get_hash_midpoint(&self, target_slot: Slot) -> Option<&[u8; HASH_BYTES]> {
        // Use the standard binary search helper to find the entry
        self.binary_search_slot_midpoint(target_slot)
            .and_then(|idx| self.get_entry(idx)) // Use safe get_entry after finding index
            .map(|entry| &entry.hash)
    }

    /// Finds the position (index) of a specific slot using standard (unweighted) binary search.
    ///
    /// Returns the index if the slot is found, or `None` if not found.
    /// Assumes entries are sorted by slot in descending order.
    #[inline(always)]
    pub fn position_midpoint(&self, target_slot: Slot) -> Option<usize> {
        // Use the standard binary search helper directly
        self.binary_search_slot_midpoint(target_slot)
    }
}

// Implementation block specific to the safe Ref version
impl<'a> SlotHashes<Ref<'a, [u8]>> {
    /// Creates a `SlotHashes` instance by safely borrowing data from an `AccountInfo`.
    ///
    /// This function verifies that:
    /// - The account key matches the `SLOTHASHES_ID`
    /// - The data contains a valid length prefix
    /// - The data is sufficiently large to hold the indicated number of entries
    ///
    /// Returns `ProgramError::InvalidArgument` if the account key doesn't match `ID`.
    /// Returns `ProgramError::AccountDataTooSmall` if the data is too short.
    /// Returns `ProgramError::InvalidAccountData` if the data length is inconsistent.
    /// Returns `ProgramError::AccountBorrowFailed` if the data cannot be borrowed.
    #[inline(always)]
    pub fn from_account_info(account_info: &'a AccountInfo) -> Result<Self, ProgramError> {
        if account_info.key() != &SLOTHASHES_ID {
            return Err(ProgramError::InvalidArgument);
        }
        
        let data_ref = account_info.try_borrow_data()?;
        
        // Parse and validate the data to get the entry count
        let (num_entries, _) = Self::parse_and_validate_data(&data_ref)?;
        
        // Construct using the unsafe constructor, providing the validated Ref and count
        // Safety: We performed the necessary checks above.
        Ok(unsafe { Self::new_unchecked(data_ref, num_entries) })
    }
}

// --- Standalone Unsafe Access Functions ---

/// Reads the entry count directly from the beginning of a byte slice **without validation**.
/// (This is identical to the struct method, added here for discoverability with other unchecked fns)
///
/// # Safety
///
/// This function is unsafe because it performs no checks on the input slice.
/// The caller **must** ensure that:
/// 1. `data` contains at least `NUM_ENTRIES_SIZE` (8) bytes.
/// 2. The first 8 bytes represent a valid `u64` in little-endian format.
/// 3. Calling this function without ensuring the above may lead to panics
///    (out-of-bounds access) or incorrect results.
#[inline(always)]
pub unsafe fn get_entry_count_unchecked(data: &[u8]) -> usize {
    // Unsafe access: assumes data has at least NUM_ENTRIES_SIZE bytes.
    let len_bytes: [u8; NUM_ENTRIES_SIZE] = data
        .get_unchecked(0..NUM_ENTRIES_SIZE)
        .try_into()
        .unwrap_unchecked();
    let num_entries = u64::from_le_bytes(len_bytes);
    (num_entries as usize).min(MAX_ENTRIES) // Cap at MAX_ENTRIES
}

/// Performs an **unsafe** interpolation binary search directly on a raw byte slice.
///
/// # Safety
/// Caller must guarantee `data` contains a valid `SlotHashes` structure.
#[inline(always)]
pub unsafe fn position_from_slice_unchecked(data: &[u8], target_slot: Slot) -> Option<usize> {
    let len = get_entry_count_unchecked(data);
    if len == 0 {
        return None;
    }
    let first_slot = u64::from_le_bytes(
        data.get_unchecked(NUM_ENTRIES_SIZE..NUM_ENTRIES_SIZE + SLOT_SIZE)
            .try_into()
            .unwrap_unchecked(),
    );

    if target_slot > first_slot {
        return None;
    }
    if target_slot == first_slot {
        return Some(0);
    }

    let mut low = 0;
    let mut high = len;
    let entries_data_start = NUM_ENTRIES_SIZE;

    while low < high {
        let delta_slots = first_slot - target_slot;
        let estimated_index = ((delta_slots * 19) / 20) as usize;
        let mid = estimated_index.clamp(low, high.saturating_sub(1));

        let entry_offset = entries_data_start + mid * ENTRY_SIZE;
        let entry_bytes = data.get_unchecked(entry_offset..(entry_offset + ENTRY_SIZE));
        let entry_slot = u64::from_le_bytes(
            entry_bytes
                .get_unchecked(0..SLOT_SIZE)
                .try_into()
                .unwrap_unchecked(),
        );

        match entry_slot.cmp(&target_slot) {
            core::cmp::Ordering::Equal => return Some(mid),
            core::cmp::Ordering::Greater => {
                let slot_diff = entry_slot - target_slot;
                let max_possible_index = mid + slot_diff as usize;
                low = mid + 1;
                high = high.min(max_possible_index + 1);
            }
            core::cmp::Ordering::Less => {
                let slot_diff = target_slot - entry_slot;
                let min_possible_index = mid.saturating_sub(slot_diff as usize);
                high = mid;
                low = low.max(min_possible_index);
            }
        }
        if low >= high {
            break;
        }
    }
    None
}

/// Performs an **unsafe** standard midpoint binary search directly on a raw byte slice.
///
/// # Safety
/// Caller must guarantee `data` contains a valid `SlotHashes` structure.
#[inline(always)]
pub unsafe fn position_midpoint_from_slice_unchecked(
    data: &[u8],
    target_slot: Slot,
) -> Option<usize> {
    let len = get_entry_count_unchecked(data);
    if len == 0 {
        return None;
    }

    let mut low = 0;
    let mut high = len;
    let entries_data_start = NUM_ENTRIES_SIZE;

    while low < high {
        let mid = low + (high - low) / 2;
        let entry_offset = entries_data_start + mid * ENTRY_SIZE;
        let entry_bytes = data.get_unchecked(entry_offset..(entry_offset + ENTRY_SIZE));
        let entry_slot = u64::from_le_bytes(
            entry_bytes
                .get_unchecked(0..SLOT_SIZE)
                .try_into()
                .unwrap_unchecked(),
        );

        match entry_slot.cmp(&target_slot) {
            core::cmp::Ordering::Equal => return Some(mid),
            core::cmp::Ordering::Less => high = mid,
            core::cmp::Ordering::Greater => low = mid + 1,
        }
    }
    None
}

/// Gets a reference to the hash for a specific slot from a raw byte slice **without validation**.
///
/// # Safety
/// Caller must guarantee `data` contains a valid `SlotHashes` structure.
#[inline(always)]
pub unsafe fn get_hash_from_slice_unchecked(
    data: &[u8],
    target_slot: Slot,
) -> Option<&[u8; HASH_BYTES]> {
    position_from_slice_unchecked(data, target_slot).map(|index| {
        let entry_offset = NUM_ENTRIES_SIZE + index * ENTRY_SIZE;
        let hash_offset = entry_offset + SLOT_SIZE;
        let hash_bytes = data.get_unchecked(hash_offset..(hash_offset + HASH_BYTES));
        &*(hash_bytes.as_ptr() as *const [u8; HASH_BYTES])
    })
}

/// Gets a reference to the hash for a specific slot from a raw byte slice using midpoint search **without validation**.
///
/// # Safety
/// Caller must guarantee `data` contains a valid `SlotHashes` structure.
#[inline(always)]
pub unsafe fn get_hash_midpoint_from_slice_unchecked(
    data: &[u8],
    target_slot: Slot,
) -> Option<&[u8; HASH_BYTES]> {
    position_midpoint_from_slice_unchecked(data, target_slot).map(|index| {
        let entry_offset = NUM_ENTRIES_SIZE + index * ENTRY_SIZE;
        let hash_offset = entry_offset + SLOT_SIZE;
        let hash_bytes = data.get_unchecked(hash_offset..(hash_offset + HASH_BYTES));
        &*(hash_bytes.as_ptr() as *const [u8; HASH_BYTES])
    })
}

/// Gets a reference to the `SlotHashEntry` at a specific index from a raw byte slice **without validation**.
///
/// # Safety
/// Caller must guarantee `data` contains a valid `SlotHashes` structure and that `index` is less than the entry count derived from the data's prefix.
#[inline(always)]
pub unsafe fn get_entry_from_slice_unchecked(data: &[u8], index: usize) -> &SlotHashEntry {
    let entry_offset = NUM_ENTRIES_SIZE + index * ENTRY_SIZE;
    let entry_bytes = data.get_unchecked(entry_offset..(entry_offset + ENTRY_SIZE));
    &*(entry_bytes.as_ptr() as *const SlotHashEntry)
}

// Note: This implementation does *not* implement the `Sysvar` trait from
// `solana_program::sysvar`. That trait typically requires deserialization
// (e.g., via `borsh` or `serde`), which is explicitly avoided here for efficiency
// and to handle the large size of `SlotHashes`. Instead, use `SlotHashes::from_account_info`
// (for the safe, borrow-checked version) or `AccountInfo::borrow_data_unchecked`, 
// `SlotHashes::get_entry_count_unchecked`, and `SlotHashes::new_unchecked` (for the 
// maximally performant, unsafe version). Linear iteration is available via the
// standard `Iterator` trait implementation.

/// Iterator over the entries in `SlotHashes`.
/// 
/// Yields references `&'s SlotHashEntry` tied to the lifetime `'s` of the borrow
/// of the `SlotHashes` instance.
pub struct SlotHashesIterator<'s, T> 
where 
    T: Deref<Target = [u8]>,
{
    slot_hashes: &'s SlotHashes<T>,
    current_index: usize,
}

// Implement Iterator trait for the custom iterator struct
impl<'s, T> Iterator for SlotHashesIterator<'s, T> 
where 
    T: Deref<Target = [u8]>,
{
    type Item = &'s SlotHashEntry;

    fn next(&mut self) -> Option<Self::Item> {
        // Use the safe get_entry method from SlotHashes
        let entry = self.slot_hashes.get_entry(self.current_index);
        if entry.is_some() {
            self.current_index += 1;
        }
        entry
    }

    // Provide size hint for potential optimizations
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.slot_hashes.len().saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}

// Implement ExactSizeIterator as we know the exact length
impl<T> ExactSizeIterator for SlotHashesIterator<'_, T> where T: Deref<Target = [u8]> {}

// Implement IntoIterator for references to SlotHashes
// This allows using `for entry in &slot_hashes { ... }`
impl<'s, T> IntoIterator for &'s SlotHashes<T> 
where 
    T: Deref<Target = [u8]>,
{
    type Item = &'s SlotHashEntry;
    type IntoIter = SlotHashesIterator<'s, T>;

    fn into_iter(self) -> Self::IntoIter {
        SlotHashesIterator {
            slot_hashes: self,
            current_index: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};
    extern crate std; // Needed for Vec in tests
    use std::vec::Vec;

    // Test the layout constants (works in both std and no_std)
    #[test]
    fn test_layout_constants() {
        assert_eq!(NUM_ENTRIES_SIZE, size_of::<u64>());
        assert_eq!(SLOT_SIZE, size_of::<u64>());
        assert_eq!(HASH_BYTES, 32);
        assert_eq!(ENTRY_SIZE, size_of::<u64>() + 32);
        assert_eq!(size_of::<SlotHashEntry>(), ENTRY_SIZE);
        assert_eq!(align_of::<SlotHashEntry>(), align_of::<u64>());
    }

    // Tests requiring std (Vec, allocation)
    #[cfg(feature = "std")]
    mod std_tests {
        use super::*;
        use std::{vec, vec::Vec};

        // Helper function to generate mock SlotHashes entries for tests
        fn generate_mock_entries(
            num_entries: usize,
            start_slot: u64,
            strategy: DecrementStrategy,
        ) -> Vec<(u64, [u8; 32])> {
            let mut entries = Vec::with_capacity(num_entries);
            let mut current_slot = start_slot;
            for i in 0..num_entries {
                let hash_byte = (i % 256) as u8;
                let hash = [hash_byte; 32];
                entries.push((current_slot, hash));
                let random_val = simple_prng(i as u64);
                let decrement = match strategy {
                    DecrementStrategy::Strictly1 => 1,
                    DecrementStrategy::Average1_05 => {
                        if random_val % 20 == 0 {
                            2
                        } else {
                            1
                        }
                    }
                    DecrementStrategy::Average2 => {
                        if random_val % 2 == 0 {
                            1
                        } else {
                            3
                        }
                    }
                };
                current_slot = current_slot.saturating_sub(decrement);
            }
            entries
        }

        // Helper function create mock data buffer (used by std and no_std tests)
        fn create_mock_data(entries: &[(u64, [u8; 32])]) -> Vec<u8> {
            let num_entries = entries.len() as u64;
            let data_len = NUM_ENTRIES_SIZE + entries.len() * ENTRY_SIZE;
            let mut data = std::vec![0u8; data_len];
            data[0..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries.to_le_bytes()); // Now safe to write prefix
            let mut offset = NUM_ENTRIES_SIZE;
            for (slot, hash) in entries {
                data[offset..offset + SLOT_SIZE].copy_from_slice(&slot.to_le_bytes());
                data[offset + SLOT_SIZE..offset + ENTRY_SIZE].copy_from_slice(hash);
                offset += ENTRY_SIZE;
            }
            data
        }
        
        #[test]
        fn test_get_entry_count_logic() { 
            let mock_entries = generate_mock_entries(3, 100, DecrementStrategy::Strictly1);
            let data = create_mock_data(&mock_entries);
            
            // Test the safe count getter
            let result = SlotHashes::<&[u8]>::get_entry_count(&data); // Specify type for assoc fn
            assert!(result.is_ok());
            let len = result.unwrap();
            assert_eq!(len, 3);
            
            // Test the unsafe count getter
            let unsafe_len = unsafe { SlotHashes::<&[u8]>::get_entry_count_unchecked(&data) };
            assert_eq!(unsafe_len, 3);
            
            assert!(SlotHashes::<&[u8]>::get_entry_count(&data[0..NUM_ENTRIES_SIZE - 1]).is_err());
            assert!(SlotHashes::<&[u8]>::get_entry_count(
                &data[0..NUM_ENTRIES_SIZE + 2 * ENTRY_SIZE]
            )
            .is_err());
            assert!(SlotHashes::<&[u8]>::get_entry_count(
                &data[0..NUM_ENTRIES_SIZE + 3 * ENTRY_SIZE]
            )
            .is_ok());
            
            let empty_data = create_mock_data(&[]);
            let empty_len = SlotHashes::<&[u8]>::get_entry_count(&empty_data).unwrap();
            assert_eq!(empty_len, 0);
            let unsafe_empty_len =
                unsafe { SlotHashes::<&[u8]>::get_entry_count_unchecked(&empty_data) };
            assert_eq!(unsafe_empty_len, 0);
        }
        
        #[test]
        fn test_binary_search_and_linear() {
            const NUM_ENTRIES: usize = 10;
            const START_SLOT: u64 = 100;
            let mock_entries =
                generate_mock_entries(NUM_ENTRIES, START_SLOT, DecrementStrategy::Average1_05);
            let mock_data = create_mock_data(&mock_entries);
            let count = mock_entries.len();
            let slot_hashes = unsafe { SlotHashes::new_unchecked(mock_data.as_slice(), count) };

            let first_slot = mock_entries[0].0;
            let last_slot = mock_entries[NUM_ENTRIES - 1].0;
            let mid_slot = mock_entries[NUM_ENTRIES / 2].0;
            
            // Test binary search position
            assert_eq!(slot_hashes.position(first_slot), Some(0));
            assert_eq!(slot_hashes.position(mid_slot), Some(NUM_ENTRIES / 2));
            assert_eq!(slot_hashes.position(last_slot), Some(NUM_ENTRIES - 1));

            // Find an actual gap to test a guaranteed non-existent internal slot
            let mut missing_internal_slot = None;
            for i in 0..(mock_entries.len() - 1) {
                if mock_entries[i].0 > mock_entries[i + 1].0 + 1 {
                    missing_internal_slot = Some(mock_entries[i + 1].0 + 1);
                    break;
                }
            }
            if let Some(missing_slot) = missing_internal_slot {
                assert_eq!(slot_hashes.position(missing_slot), None); // Test interpolation search miss
            } else {
                std::println!("[WARN] Could not find internal gap for missing slot test in std_tests");
            }
            assert_eq!(slot_hashes.position(last_slot.saturating_sub(1)), None); // Test near end (usually none)
            
            // Test standard binary search position
            assert_eq!(slot_hashes.position_midpoint(first_slot), Some(0));
            assert_eq!(
                slot_hashes.position_midpoint(mid_slot),
                Some(NUM_ENTRIES / 2)
            );
            assert_eq!(
                slot_hashes.position_midpoint(last_slot),
                Some(NUM_ENTRIES - 1)
            );
            assert_eq!(slot_hashes.position_midpoint(START_SLOT + 1), None);
            if let Some(missing_slot) = missing_internal_slot {
                assert_eq!(slot_hashes.position_midpoint(missing_slot), None); // Test midpoint search miss
            }
            assert_eq!(
                slot_hashes.position_midpoint(last_slot.saturating_sub(1)),
                None
            ); // Test near end (usually none)
            
            // Test binary search get_hash
            assert_eq!(slot_hashes.get_hash(first_slot), Some(&mock_entries[0].1));
            assert_eq!(
                slot_hashes.get_hash(mid_slot),
                Some(&mock_entries[NUM_ENTRIES / 2].1)
            );
            assert_eq!(slot_hashes.get_hash(START_SLOT + 1), None);
            
            // Test standard binary search get_hash
            assert_eq!(
                slot_hashes.get_hash_midpoint(first_slot),
                Some(&mock_entries[0].1)
            );
            assert_eq!(
                slot_hashes.get_hash_midpoint(mid_slot),
                Some(&mock_entries[NUM_ENTRIES / 2].1)
            );
            assert_eq!(slot_hashes.get_hash_midpoint(START_SLOT + 1), None);
            
            // Test empty
            let empty_data = create_mock_data(&[]);
            let empty_hashes = unsafe { SlotHashes::new_unchecked(empty_data.as_slice(), 0) };
            assert_eq!(empty_hashes.position(100), None);
            assert_eq!(empty_hashes.position_midpoint(100), None);
        }

        #[test]
        fn test_basic_getters_and_iterator() {
            const NUM_ENTRIES: usize = 5;
            const START_SLOT: u64 = 100;
            let mock_entries =
                generate_mock_entries(NUM_ENTRIES, START_SLOT, DecrementStrategy::Strictly1);
            let data = create_mock_data(&mock_entries);
            let count = mock_entries.len();
            let slot_hashes = unsafe { SlotHashes::new_unchecked(data.as_slice(), count) };

            // Test len() and is_empty()
            assert_eq!(slot_hashes.len(), NUM_ENTRIES);
            assert!(!slot_hashes.is_empty());

            // Test get_entry()
            let entry0 = slot_hashes.get_entry(0);
            assert!(entry0.is_some());
            assert_eq!(entry0.unwrap().slot, mock_entries[0].0);
            assert_eq!(entry0.unwrap().hash, mock_entries[0].1);

            let entry2 = slot_hashes.get_entry(NUM_ENTRIES - 1); // Last entry
            assert!(entry2.is_some());
            assert_eq!(entry2.unwrap().slot, mock_entries[NUM_ENTRIES - 1].0);
            assert_eq!(entry2.unwrap().hash, mock_entries[NUM_ENTRIES - 1].1);

            // Test get_entry() out of bounds
            assert!(slot_hashes.get_entry(NUM_ENTRIES).is_none());

            // Test iterator
            let mut iter = slot_hashes.into_iter();
            for i in 0..NUM_ENTRIES {
                assert_eq!(iter.next().unwrap().slot, mock_entries[i].0);
            }
            assert!(iter.next().is_none());

            // Test ExactSizeIterator hint
            let mut iter_hint = slot_hashes.into_iter();
            assert_eq!(iter_hint.size_hint(), (NUM_ENTRIES, Some(NUM_ENTRIES)));
            iter_hint.next();
            assert_eq!(
                iter_hint.size_hint(),
                (NUM_ENTRIES - 1, Some(NUM_ENTRIES - 1))
            );
            // Skip to end
            for _ in 1..NUM_ENTRIES {
            iter_hint.next();
            }
            iter_hint.next();
            assert_eq!(iter_hint.size_hint(), (0, Some(0)));

            // Test empty case
            let empty_data = create_mock_data(&[]);
            let empty_hashes = unsafe { SlotHashes::new_unchecked(empty_data.as_slice(), 0) };
            assert_eq!(empty_hashes.len(), 0);
            assert!(empty_hashes.is_empty());
            assert!(empty_hashes.get_entry(0).is_none());
            assert!(empty_hashes.into_iter().next().is_none());
        }
        
        #[test]
        fn test_from_bytes() {
            let mock_entries = generate_mock_entries(2, 100, DecrementStrategy::Strictly1);
            let data = create_mock_data(&mock_entries);
            
            // Valid data
            let count_res = SlotHashes::<&[u8]>::from_bytes(&data);
            assert!(count_res.is_ok());
            assert_eq!(count_res.unwrap(), 2);

            // Data too small (less than len prefix)
            let short_data_1 = &data[0..NUM_ENTRIES_SIZE - 1];
            let res1 = SlotHashes::<&[u8]>::from_bytes(short_data_1);
            assert!(matches!(res1, Err(ProgramError::AccountDataTooSmall)));

            // Data too small (correct len prefix, but not enough data for entries)
            let short_data_2 = &data[0..NUM_ENTRIES_SIZE + ENTRY_SIZE]; // Only space for 1 entry
            let res2 = SlotHashes::<&[u8]>::from_bytes(short_data_2);
            assert!(matches!(res2, Err(ProgramError::InvalidAccountData)));
            
            // Empty data is valid
            let empty_data = create_mock_data(&[]);
             let empty_res = SlotHashes::<&[u8]>::from_bytes(&empty_data);
            assert!(empty_res.is_ok());
            assert_eq!(empty_res.unwrap(), 0);
        }
        
        #[test]
        fn test_get_entry_unchecked() {
            let mock_entries = generate_mock_entries(1, 100, DecrementStrategy::Strictly1);
            let data = create_mock_data(&mock_entries);
            let slot_hashes = unsafe { SlotHashes::new_unchecked(data.as_slice(), 1) };
            
            // Safety: index 0 is valid because len is 1
            let entry = unsafe { slot_hashes.get_entry_unchecked(0) };
            assert_eq!(entry.slot, mock_entries[0].0);
            assert_eq!(entry.hash, mock_entries[0].1);
            // Note: Accessing index 1 here would be UB and is not tested.
        }

        #[test]
        fn test_unchecked_static_functions() {
            const NUM_ENTRIES: usize = 10;
            const START_SLOT: u64 = 100;
            let mock_entries =
                generate_mock_entries(NUM_ENTRIES, START_SLOT, DecrementStrategy::Average1_05);
            let data = create_mock_data(&mock_entries);

            let first_slot = mock_entries[0].0;
            let mid_index = NUM_ENTRIES / 2;
            let mid_slot = mock_entries[mid_index].0;
            let last_slot = mock_entries[NUM_ENTRIES - 1].0;
            let missing_slot_high = START_SLOT + 1;
            let missing_slot_low = mock_entries.last().unwrap().0 - 1;

            // Safety: We guarantee `data` is valid based on `create_mock_data`
            unsafe {
                // Test get_entry_count_unchecked (already tested elsewhere, but confirm here)
                assert_eq!(get_entry_count_unchecked(&data), NUM_ENTRIES);

                // Test position_from_slice_unchecked
                assert_eq!(position_from_slice_unchecked(&data, first_slot), Some(0));
                assert_eq!(
                    position_from_slice_unchecked(&data, mid_slot),
                    Some(mid_index)
                );
                assert_eq!(
                    position_from_slice_unchecked(&data, last_slot),
                    Some(NUM_ENTRIES - 1)
                );
                assert_eq!(
                    position_from_slice_unchecked(&data, missing_slot_high),
                    None
                );
                assert_eq!(position_from_slice_unchecked(&data, missing_slot_low), None);

                // Test get_hash_from_slice_unchecked
                assert_eq!(
                    get_hash_from_slice_unchecked(&data, first_slot),
                    Some(&mock_entries[0].1)
                );
                assert_eq!(
                    get_hash_from_slice_unchecked(&data, mid_slot),
                    Some(&mock_entries[mid_index].1)
                );
                assert_eq!(
                    get_hash_from_slice_unchecked(&data, last_slot),
                    Some(&mock_entries[NUM_ENTRIES - 1].1)
                );
                assert_eq!(
                    get_hash_from_slice_unchecked(&data, missing_slot_high),
                    None
                );
                assert_eq!(get_hash_from_slice_unchecked(&data, missing_slot_low), None);

                // Test get_entry_from_slice_unchecked
                let entry0 = get_entry_from_slice_unchecked(&data, 0);
                assert_eq!(entry0.slot, first_slot);
                assert_eq!(entry0.hash, mock_entries[0].1);
                let entry_last = get_entry_from_slice_unchecked(&data, NUM_ENTRIES - 1);
                assert_eq!(entry_last.slot, last_slot);
                assert_eq!(entry_last.hash, mock_entries[NUM_ENTRIES - 1].1);
            }

            // Test empty case for unchecked functions
            let empty_data = create_mock_data(&[]);
            unsafe {
                assert_eq!(get_entry_count_unchecked(&empty_data), 0);
                assert_eq!(position_from_slice_unchecked(&empty_data, 100), None);
                assert_eq!(get_hash_from_slice_unchecked(&empty_data, 100), None);
                // Calling get_entry_from_slice_unchecked with index 0 on empty data is UB, not tested.
            }
        }
    }

    // --- Copied from benchmark setup for no_std test generation ---
    #[derive(Clone, Copy, Debug)]
    enum DecrementStrategy {
        Strictly1,
        Average1_05,
        Average2,
    }
    fn simple_prng(seed: u64) -> u64 {
        const A: u64 = 16807;
        const M: u64 = 2147483647;
        let initial_state = if seed == 0 { 1 } else { seed };
        (A.wrapping_mul(initial_state)) % M
    }
    fn generate_mock_entries(
        num_entries: usize,
        start_slot: u64,
        strategy: DecrementStrategy,
    ) -> Vec<(Slot, [u8; 32])> {
        let mut entries = Vec::with_capacity(num_entries);
        let mut current_slot = start_slot;
        for i in 0..num_entries {
            let hash_byte = (i % 256) as u8;
            let hash = [hash_byte; 32];
            entries.push((current_slot, hash));
            let random_val = simple_prng(i as u64);
            let decrement = match strategy {
                DecrementStrategy::Strictly1 => 1,
                DecrementStrategy::Average1_05 => {
                    if random_val % 20 == 0 {
                        2
                    } else {
                        1
                    }
                }
                DecrementStrategy::Average2 => {
                    if random_val % 2 == 0 {
                        1
                    } else {
                        3
                    }
                }
            };
            current_slot = current_slot.saturating_sub(decrement);
        }
        entries
    }
    fn create_mock_data_no_std(entries: &[(Slot, [u8; 32])]) -> Vec<u8> {
        let num_entries = entries.len() as u64;
        let data_len = NUM_ENTRIES_SIZE + entries.len() * ENTRY_SIZE;
        let mut data = std::vec![0u8; data_len];
        data[0..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries.to_le_bytes()); // Now safe to write prefix
        let mut offset = NUM_ENTRIES_SIZE;
        for (slot, hash) in entries {
            data[offset..offset + SLOT_SIZE].copy_from_slice(&slot.to_le_bytes());
            data[offset + SLOT_SIZE..offset + ENTRY_SIZE].copy_from_slice(hash.as_ref()); // Use AsRef
            offset += ENTRY_SIZE;
        }
        data
    }
    // --- End copied helpers ---
    
    // No-std compatible version of binary search test using arrays
    #[test]
    fn test_binary_search_no_std() {
        const TEST_NUM_ENTRIES: usize = 512;
        const START_SLOT: u64 = 2000;

        // Generate entries using Avg1.05 strategy
        let entries =
            generate_mock_entries(TEST_NUM_ENTRIES, START_SLOT, DecrementStrategy::Average1_05);
        let data = create_mock_data_no_std(&entries);
        let entry_count = entries.len();

        // Get first, middle, and last generated slots for testing
        let first_slot = entries[0].0;
        let mid_index = entry_count / 2;
        let mid_slot = entries[mid_index].0;
        let last_slot = entries[entry_count - 1].0;
        
        // Create SlotHashes using the unsafe constructor with a slice
        let slot_hashes = unsafe { SlotHashes::new_unchecked(data.as_slice(), entry_count) };

        // Test the default (interpolation) binary search algorithm
        assert_eq!(slot_hashes.position(first_slot), Some(0));

        // --- Detailed check for mid_slot ---
        let expected_mid_index = Some(mid_index);
        let actual_pos_mid = slot_hashes.position(mid_slot);
        if actual_pos_mid != expected_mid_index {
            // Extract surrounding entries for context
            let start_idx = mid_index.saturating_sub(2);
            let end_idx = core::cmp::min(entry_count, mid_index.saturating_add(3));
            let surrounding_entries: std::vec::Vec<_> =
                entries[start_idx..end_idx].iter().map(|e| e.0).collect(); // Use std::vec! here
            panic!(
                "Assertion `position({}) == {:?}` failed! Actual: {:?}. Surrounding slots: {:?}",
                mid_slot, expected_mid_index, actual_pos_mid, surrounding_entries
            );
        }
        // --- End Detailed check ---
        assert_eq!(actual_pos_mid, expected_mid_index); // Re-assert after check/panic

        assert_eq!(slot_hashes.position(last_slot), Some(entry_count - 1));

        // Test non-existent slots
        assert_eq!(slot_hashes.position(START_SLOT + 1), None); // Slot above start

        // Find an actual gap to test a guaranteed non-existent internal slot
        let mut missing_internal_slot = None;
        for i in 0..(entries.len() - 1) {
            if entries[i].0 > entries[i + 1].0 + 1 {
                missing_internal_slot = Some(entries[i + 1].0 + 1);
                break;
            }
        }
        if let Some(missing_slot) = missing_internal_slot {
            assert_eq!(slot_hashes.position(missing_slot), None);
        } else {
            // panic! or log if needed: cannot test internal miss without a gap
        }

        // Test get_hash (interpolation)
        assert_eq!(slot_hashes.get_hash(first_slot), Some(&entries[0].1));
        assert_eq!(slot_hashes.get_hash(mid_slot), Some(&entries[mid_index].1));
        assert_eq!(
            slot_hashes.get_hash(last_slot),
            Some(&entries[entry_count - 1].1)
        );
        assert_eq!(slot_hashes.get_hash(START_SLOT + 1), None);

        // Conditionally test midpoint functions if feature enabled
        {
            // Test standard binary search position
            assert_eq!(slot_hashes.position_midpoint(first_slot), Some(0));
            assert_eq!(slot_hashes.position_midpoint(mid_slot), Some(mid_index));
            assert_eq!(
                slot_hashes.position_midpoint(last_slot),
                Some(entry_count - 1)
            );
            assert_eq!(slot_hashes.position_midpoint(START_SLOT + 1), None);
            if let Some(missing_slot) = missing_internal_slot {
                assert_eq!(slot_hashes.position_midpoint(missing_slot), None);
            }
            assert_eq!(
                slot_hashes.position_midpoint(last_slot.saturating_sub(1)),
                None
            );

            // Test standard binary search get_hash
            assert_eq!(
                slot_hashes.get_hash_midpoint(first_slot),
                Some(&entries[0].1)
            );
            assert_eq!(
                slot_hashes.get_hash_midpoint(mid_slot),
                Some(&entries[mid_index].1)
            );
            assert_eq!(
                slot_hashes.get_hash_midpoint(last_slot),
                Some(&entries[entry_count - 1].1)
            );
            assert_eq!(slot_hashes.get_hash_midpoint(START_SLOT + 1), None);
        }

        // Test empty list explicitly
        let empty_entries = generate_mock_entries(0, START_SLOT, DecrementStrategy::Strictly1);
        let empty_data = create_mock_data_no_std(&empty_entries);
        let empty_hashes = unsafe { SlotHashes::new_unchecked(empty_data.as_slice(), 0) };
        assert_eq!(empty_hashes.get_hash(100), None);
        assert_eq!(empty_hashes.get_hash_midpoint(100), None);

        // --- Add Panic for failing assertion to see context ---
        let pos_start_plus_1 = slot_hashes.position(START_SLOT + 1);
        if pos_start_plus_1.is_some() {
            panic!(
                "Assertion `position(START_SLOT + 1) == None` failed! mid_slot={}, Found: {:?}",
                mid_slot, pos_start_plus_1
            );
        }
        // --- End Panic ---
        assert_eq!(pos_start_plus_1, None);
    }

    // No-std compatible tests
    #[test]
    fn test_basic_getters_and_iterator_no_std() {
        const NUM_ENTRIES: usize = 5;
        const START_SLOT: u64 = 100;
        let entries = generate_mock_entries(NUM_ENTRIES, START_SLOT, DecrementStrategy::Strictly1);
        let data = create_mock_data_no_std(&entries);
        let slot_hashes = unsafe { SlotHashes::new_unchecked(data.as_slice(), NUM_ENTRIES) };

        // Test len() and is_empty()
        assert_eq!(slot_hashes.len(), NUM_ENTRIES);
        assert!(!slot_hashes.is_empty());

        // Test get_entry()
        let entry0 = slot_hashes.get_entry(0);
        assert!(entry0.is_some());
        assert_eq!(entry0.unwrap().slot, START_SLOT); // Check against start slot
        assert_eq!(entry0.unwrap().hash, [0u8; HASH_BYTES]); // First generated hash is [0u8; 32]

        let entry2 = slot_hashes.get_entry(NUM_ENTRIES - 1); // Last entry
        assert!(entry2.is_some());
        // Check last entry against generated data
        assert_eq!(entry2.unwrap().slot, entries[NUM_ENTRIES - 1].0);
        assert_eq!(entry2.unwrap().hash, entries[NUM_ENTRIES - 1].1);
        assert!(slot_hashes.get_entry(NUM_ENTRIES).is_none()); // Out of bounds

        // Test iterator
        let mut iter = slot_hashes.into_iter();
        for i in 0..NUM_ENTRIES {
            let next_entry = iter.next().unwrap();
            assert_eq!(next_entry.slot, entries[i].0);
            assert_eq!(next_entry.hash, entries[i].1);
        }
        assert!(iter.next().is_none());

        // Test ExactSizeIterator hint
        let mut iter_hint = slot_hashes.into_iter();
        assert_eq!(iter_hint.size_hint(), (NUM_ENTRIES, Some(NUM_ENTRIES)));
        iter_hint.next();
        assert_eq!(
            iter_hint.size_hint(),
            (NUM_ENTRIES - 1, Some(NUM_ENTRIES - 1))
        );
        // Skip to end
        for _ in 1..NUM_ENTRIES {
            iter_hint.next();
        }
        iter_hint.next();
        assert_eq!(iter_hint.size_hint(), (0, Some(0)));

        // Test empty case
        let empty_data = create_mock_data_no_std(&[]);
        let empty_hashes = unsafe { SlotHashes::new_unchecked(empty_data.as_slice(), 0) };
        assert_eq!(empty_hashes.len(), 0);
        assert!(empty_hashes.is_empty());
        assert!(empty_hashes.get_entry(0).is_none());
        assert!(empty_hashes.into_iter().next().is_none());
    }

    #[test]
    fn test_from_bytes_no_std() {
        // Valid data (2 entries)
        let entries: &[(Slot, [u8; HASH_BYTES])] =
            &[(100, [1u8; HASH_BYTES]), (98, [2u8; HASH_BYTES])];
        let num_entries_bytes = (entries.len() as u64).to_le_bytes();
        const TEST_LEN: usize = 2;
        let mut raw_data = [0u8; NUM_ENTRIES_SIZE + TEST_LEN * ENTRY_SIZE];
        raw_data[..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries_bytes);
        let mut cursor = NUM_ENTRIES_SIZE;
        for (slot, hash) in entries {
            raw_data[cursor..cursor + SLOT_SIZE].copy_from_slice(&slot.to_le_bytes());
            cursor += SLOT_SIZE;
            raw_data[cursor..cursor + HASH_BYTES].copy_from_slice(hash.as_ref());
            cursor += HASH_BYTES;
        }
        let data_slice = &raw_data[..cursor];
        let count_res = SlotHashes::<&[u8]>::from_bytes(data_slice);
        assert!(count_res.is_ok());
        assert_eq!(count_res.unwrap(), 2);

        // Data too small (less than len prefix)
        let short_data_1 = &data_slice[0..NUM_ENTRIES_SIZE - 1];
        let res1 = SlotHashes::<&[u8]>::from_bytes(short_data_1);
        assert!(matches!(res1, Err(ProgramError::AccountDataTooSmall)));

        // Data too small (correct len prefix, but not enough data for entries)
        // Use the same raw_data but slice it to be too short
        let short_data_2 = &data_slice[0..NUM_ENTRIES_SIZE + ENTRY_SIZE]; // Only space for 1 entry
        let res2 = SlotHashes::<&[u8]>::from_bytes(short_data_2);
        assert!(matches!(res2, Err(ProgramError::InvalidAccountData)));

        // Empty data is valid
        let empty_num_bytes = (0u64).to_le_bytes();
        let mut empty_raw_data = [0u8; NUM_ENTRIES_SIZE];
        empty_raw_data[..NUM_ENTRIES_SIZE].copy_from_slice(&empty_num_bytes);
        let empty_res = SlotHashes::<&[u8]>::from_bytes(empty_raw_data.as_slice());
        assert!(empty_res.is_ok());
        assert_eq!(empty_res.unwrap(), 0);
    }
    
    #[test]
    fn test_get_entry_unchecked_no_std() {
         let single_entry: &[(Slot, [u8; HASH_BYTES])] = &[(100, [1u8; HASH_BYTES])];
         let num_entries_bytes_1 = (single_entry.len() as u64).to_le_bytes();
         const TEST_LEN_1: usize = 1;
         let mut raw_data_1 = [0u8; NUM_ENTRIES_SIZE + TEST_LEN_1 * ENTRY_SIZE];
         raw_data_1[..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries_bytes_1);
        raw_data_1[NUM_ENTRIES_SIZE..NUM_ENTRIES_SIZE + SLOT_SIZE]
            .copy_from_slice(&single_entry[0].0.to_le_bytes());
        raw_data_1[NUM_ENTRIES_SIZE + SLOT_SIZE..].copy_from_slice(single_entry[0].1.as_ref());
         let slot_hashes = unsafe { SlotHashes::new_unchecked(&raw_data_1[..], 1) };

         // Safety: index 0 is valid because len is 1
         let entry = unsafe { slot_hashes.get_entry_unchecked(0) };
         assert_eq!(entry.slot, 100);
         assert_eq!(entry.hash, [1u8; HASH_BYTES]);
    }
}
