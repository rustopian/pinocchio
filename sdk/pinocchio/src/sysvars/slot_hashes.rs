//! Efficient, zero-copy access to the SlotHashes sysvar.
//!
//! This module provides a way to access the SlotHashes sysvar data
//! directly from account data without requiring full deserialization or
//! relying on potentially inefficient syscalls for individual entries.
//! No impl_sysvar_get! since the data is too huge.

use crate::{
    account_info::{AccountInfo, Ref},
    sysvars::clock::Slot,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use core::{mem, ops::Deref};

/// SysvarS1otHashes111111111111111111111111111
pub const SLOTHASHES_ID: Pubkey = [
  6, 167, 213, 23, 25, 47, 10, 175, 198, 242, 101, 227, 251, 119, 204, 122, 218, 130, 197, 41, 208, 190, 59, 19, 110, 45, 0, 85, 32, 0, 0, 0
];
pub const MAX_ENTRIES: usize = 512;
pub const HASH_BYTES: usize = 32;

/// Sysvar data is:
/// len	(8 bytes): little-endian entry count (≤ 512)
/// entries	(len × 40 bytes):	consecutive `(u64 slot, [u8;32] hash)` pairs
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
    /// Returns (number_of_entries, required_length) if valid.
    #[inline(always)]
    fn parse_and_validate_data(data: &[u8]) -> Result<(usize, usize), ProgramError> {
        if data.len() < NUM_ENTRIES_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }
        
        let len_bytes: [u8; NUM_ENTRIES_SIZE] = 
            unsafe { data.get_unchecked(0..NUM_ENTRIES_SIZE) }.try_into().unwrap();
        let num_entries = u64::from_le_bytes(len_bytes);
        let num_entries = (num_entries as usize).min(MAX_ENTRIES);
        
        let required_len = NUM_ENTRIES_SIZE.saturating_add(num_entries.saturating_mul(ENTRY_SIZE));
        if data.len() < required_len {
            return Err(ProgramError::InvalidAccountData);
        }
        
        Ok((num_entries, required_len))
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
            .unwrap_unchecked(); // Use unwrap_unchecked as per safety contract
            
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
    pub fn get_entry<'s>(&'s self, index: usize) -> Option<&'s SlotHashEntry> {
        if index >= self.len {
            return None;
        }
        // Get slice using Deref on self.data
        let full_data_slice: &'s [u8] = &*self.data;
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
    pub unsafe fn get_entry_unchecked<'s>(&'s self, index: usize) -> &'s SlotHashEntry {
        // Get slice using Deref on self.data
        let full_data_slice: &'s [u8] = &*self.data;
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
    fn binary_search_slot<'s>(&'s self, target_slot: Slot) -> Option<usize> {
        let len = self.len;
        if len == 0 {
            return None;
        }

        // Get the first slot to establish our initial bounds
        let first_slot = unsafe { self.get_entry_unchecked(0).slot };
        
        // If target is newer than newest, it can't be here
        if target_slot > first_slot {
            return None;
        }
        if target_slot == first_slot {
            return Some(0);
        }

        // We can't make assumptions about maximum gaps, so we can't reject based on
        // theoretical minimum slot anymore. Any slot less than first_slot could potentially
        // be present.

        let mut low = 0;
        let mut high = len;

        while low < high {
            // Use the slot difference to estimate where to look
            // Assume ~5% gaps (95% density) as a search heuristic
            let delta_slots = first_slot - target_slot;
            let estimated_index = ((delta_slots * 19) / 20) as usize;
            // Bound our estimate to the current search range
            let mid = estimated_index.clamp(low, high - 1);

            // Safety: `mid` is clamped to be within `[low, high - 1]`, so it's a valid index
            // because `low < high` implies `high >= 1` and `mid <= high - 1`.
            let entry_slot = unsafe { self.get_entry_unchecked(mid).slot };

            match entry_slot.cmp(&target_slot) {
                core::cmp::Ordering::Equal => return Some(mid),
                core::cmp::Ordering::Greater => {
                    // Current slot > target, so target must be after mid
                    // We can only use the minimum gap of 1 for bounds:
                    // If we're at slot 600 and want 500, the 500 must be
                    // at most 100 positions after our current position
                    let slot_diff = entry_slot - target_slot;
                    let max_possible_index = mid + slot_diff as usize;
                    low = mid + 1;
                    high = high.min(max_possible_index);
                }
                core::cmp::Ordering::Less => {
                    // Current slot < target, so target must be before mid
                    // If we're at slot 400 and want 500, we know 500 must be
                    // at least (500-400) = 100 slots before our current position
                    // (due to minimum gap of 1)
                    let slot_diff = target_slot - entry_slot;
                    let min_possible_index = mid.saturating_sub(slot_diff as usize);
                    high = mid;
                    low = low.max(min_possible_index);
                }
            }

            // If our bounds have converged or crossed, we're done
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
    fn binary_search_slot_standard<'s>(&'s self, target_slot: Slot) -> Option<usize> {
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
    pub fn get_hash<'s>(&'s self, target_slot: Slot) -> Option<&'s [u8; HASH_BYTES]> {
        // Use the binary search helper to find the entry
        self.binary_search_slot(target_slot)
            .and_then(|idx| self.get_entry(idx)) // Use safe get_entry after finding index
            .map(|entry| &entry.hash)
    }

    /// Finds the position (index) of a specific slot using binary search.
    ///
    /// Returns the index if the slot is found, or `None` if not found.
    /// Assumes entries are sorted by slot in descending order.
    #[inline(always)]
    pub fn position(&self, target_slot: Slot) -> Option<usize> {
        // Use the interpolation search helper directly
        self.binary_search_slot(target_slot)
    }

    /// Finds the hash for a specific slot using standard (unweighted) binary search.
    ///
    /// Returns the hash if the slot is found, or `None` if not found.
    /// Assumes entries are sorted by slot in descending order.
    #[inline(always)]
    pub fn get_hash_standard<'s>(&'s self, target_slot: Slot) -> Option<&'s [u8; HASH_BYTES]> {
        // Use the standard binary search helper to find the entry
        self.binary_search_slot_standard(target_slot)
            .and_then(|idx| self.get_entry(idx)) // Use safe get_entry after finding index
            .map(|entry| &entry.hash)
    }

    /// Finds the position (index) of a specific slot using standard (unweighted) binary search.
    ///
    /// Returns the index if the slot is found, or `None` if not found.
    /// Assumes entries are sorted by slot in descending order.
    #[inline(always)]
    pub fn position_standard(&self, target_slot: Slot) -> Option<usize> {
        // Use the standard binary search helper directly
        self.binary_search_slot_standard(target_slot)
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
impl<'s, T> ExactSizeIterator for SlotHashesIterator<'s, T> 
where 
    T: Deref<Target = [u8]>,
{}

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

    // Tests requiring std (Vec, allocation) are conditionally compiled
    #[cfg(feature = "std")]
    mod std_tests {
        use super::*;
        use std::{vec, vec::Vec};

        // Helper to create mock data
        fn create_mock_data(entries: &[(Slot, [u8; HASH_BYTES])]) -> Vec<u8> {
            let num_entries = entries.len() as u64;
            let mut data = Vec::with_capacity(NUM_ENTRIES_SIZE + entries.len() * ENTRY_SIZE);
            data.extend_from_slice(&num_entries.to_le_bytes());
            for (slot, hash) in entries {
                data.extend_from_slice(&slot.to_le_bytes());
                data.extend_from_slice(hash);
            }
            data
        }
        
        #[test]
        fn test_get_entry_count_logic() { 
             let mock_entries = [
                (100, [1u8; HASH_BYTES]),
                (98, [2u8; HASH_BYTES]),
                (95, [3u8; HASH_BYTES]),
            ];
            let data = create_mock_data(&mock_entries);
            
            // Test the safe count getter
            let result = SlotHashes::<&[u8]>::get_entry_count(&data); // Specify type for assoc fn
            assert!(result.is_ok());
            let len = result.unwrap();
            assert_eq!(len, 3);
            
            // Test the unsafe count getter
            let unsafe_len = unsafe { SlotHashes::<&[u8]>::get_entry_count_unchecked(&data) };
            assert_eq!(unsafe_len, 3);
            
            assert!(SlotHashes::<&[u8]>::get_entry_count(&data[0..NUM_ENTRIES_SIZE-1]).is_err());
            assert!(SlotHashes::<&[u8]>::get_entry_count(&data[0..NUM_ENTRIES_SIZE + 2 * ENTRY_SIZE]).is_err());
            assert!(SlotHashes::<&[u8]>::get_entry_count(&data[0..NUM_ENTRIES_SIZE + 3 * ENTRY_SIZE]).is_ok());
            
            let empty_data = create_mock_data(&[]);
            let empty_len = SlotHashes::<&[u8]>::get_entry_count(&empty_data).unwrap();
            assert_eq!(empty_len, 0);
            let unsafe_empty_len = unsafe { SlotHashes::<&[u8]>::get_entry_count_unchecked(&empty_data) };
            assert_eq!(unsafe_empty_len, 0);
        }
        
        #[test]
        fn test_binary_search_and_linear() {
            // Use the generic struct directly with a slice for testing
            // No need for the previous MockSlotHashes struct
            
            // Test data
            let entries_data = vec![
                SlotHashEntry { slot: 100, hash: [1u8; HASH_BYTES] },
                SlotHashEntry { slot: 98, hash: [2u8; HASH_BYTES] },
                SlotHashEntry { slot: 95, hash: [3u8; HASH_BYTES] },
                SlotHashEntry { slot: 90, hash: [4u8; HASH_BYTES] },
                SlotHashEntry { slot: 85, hash: [5u8; HASH_BYTES] },
            ];
            let mock_data = create_mock_data(&entries_data.iter().map(|e| (e.slot, e.hash)).collect::<Vec<_>>());
            let count = entries_data.len();
            let slot_hashes = unsafe { SlotHashes::new_unchecked(mock_data.as_slice(), count) };
            
            // Test binary search position
            assert_eq!(slot_hashes.position(100), Some(0));
            assert_eq!(slot_hashes.position(98), Some(1));
            assert_eq!(slot_hashes.position(95), Some(2));
            assert_eq!(slot_hashes.position(90), Some(3));
            assert_eq!(slot_hashes.position(85), Some(4));
            assert_eq!(slot_hashes.position(99), None);
            assert_eq!(slot_hashes.position(84), None);
            
            // Test standard binary search position
            assert_eq!(slot_hashes.position_standard(100), Some(0));
            assert_eq!(slot_hashes.position_standard(98), Some(1));
            assert_eq!(slot_hashes.position_standard(95), Some(2));
            assert_eq!(slot_hashes.position_standard(90), Some(3));
            assert_eq!(slot_hashes.position_standard(85), Some(4));
            assert_eq!(slot_hashes.position_standard(99), None);
            assert_eq!(slot_hashes.position_standard(84), None);
            
            // Test binary search get_hash
            assert_eq!(slot_hashes.get_hash(100), Some(&[1u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash(98), Some(&[2u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash(99), None);
            
            // Test standard binary search get_hash
            assert_eq!(slot_hashes.get_hash_standard(100), Some(&[1u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash_standard(98), Some(&[2u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash_standard(99), None);
            
            // Test empty
            let empty_data = create_mock_data(&[]);
            let empty_hashes = unsafe { SlotHashes::new_unchecked(empty_data.as_slice(), 0) };
            assert_eq!(empty_hashes.position(100), None);
            assert_eq!(empty_hashes.position_standard(100), None);
        }
        
        #[test]
        fn test_slot_hashes_max_entries_cap() {
            // Test the get_entry_count functions with capped data
            let num_entries_too_many = (MAX_ENTRIES + 10) as u64;
            let mut data = Vec::new();
            data.extend_from_slice(&num_entries_too_many.to_le_bytes());
            for i in 0..MAX_ENTRIES + 5 { 
                 data.extend_from_slice(&((MAX_ENTRIES - i) as u64).to_le_bytes()); 
                 data.extend_from_slice(&[i as u8; HASH_BYTES]);
            }

            // Safe version should cap
            let result = SlotHashes::<&[u8]>::get_entry_count(&data);
            assert!(result.is_ok());
            let len = result.unwrap();
            assert_eq!(len, MAX_ENTRIES);

            // Unsafe version should also cap
            let unsafe_len = unsafe { SlotHashes::<&[u8]>::get_entry_count_unchecked(&data) };
            assert_eq!(unsafe_len, MAX_ENTRIES);
        }

        #[test]
        fn test_basic_getters_and_iterator() {
            let mock_entries = [
                (100, [1u8; HASH_BYTES]),
                (98, [2u8; HASH_BYTES]),
                (95, [3u8; HASH_BYTES]),
            ];
            let data = create_mock_data(&mock_entries);
            let count = mock_entries.len();
            let slot_hashes = unsafe { SlotHashes::new_unchecked(data.as_slice(), count) };

            // Test len() and is_empty()
            assert_eq!(slot_hashes.len(), 3);
            assert!(!slot_hashes.is_empty());

            // Test get_entry()
            let entry0 = slot_hashes.get_entry(0);
            assert!(entry0.is_some());
            assert_eq!(entry0.unwrap().slot, 100);
            assert_eq!(entry0.unwrap().hash, [1u8; HASH_BYTES]);

            let entry2 = slot_hashes.get_entry(2);
            assert!(entry2.is_some());
            assert_eq!(entry2.unwrap().slot, 95);
            assert_eq!(entry2.unwrap().hash, [3u8; HASH_BYTES]);

            // Test get_entry() out of bounds
            assert!(slot_hashes.get_entry(3).is_none());

            // Test iterator
            let mut iter = slot_hashes.into_iter();
            assert_eq!(iter.next().unwrap().slot, 100);
            assert_eq!(iter.next().unwrap().slot, 98);
            assert_eq!(iter.next().unwrap().slot, 95);
            assert!(iter.next().is_none());

            // Test ExactSizeIterator hint
            let mut iter_hint = slot_hashes.into_iter();
            assert_eq!(iter_hint.size_hint(), (3, Some(3)));
            iter_hint.next();
            assert_eq!(iter_hint.size_hint(), (2, Some(2)));
            iter_hint.next();
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
            let mock_entries = [(100, [1u8; HASH_BYTES]), (98, [2u8; HASH_BYTES])];
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
            let mock_entries = [(100, [1u8; HASH_BYTES])];
            let data = create_mock_data(&mock_entries);
            let slot_hashes = unsafe { SlotHashes::new_unchecked(data.as_slice(), 1) };
            
            // Safety: index 0 is valid because len is 1
            let entry = unsafe { slot_hashes.get_entry_unchecked(0) };
            assert_eq!(entry.slot, 100);
            assert_eq!(entry.hash, [1u8; HASH_BYTES]);
            // Note: Accessing index 1 here would be UB and is not tested.
        }

        #[test]
        #[allow(deprecated)] // Allow use of deprecated AccountInfo fields for mocking
        fn test_from_account_info() {
             use crate::account_info::AccountInfo;
             use crate::sysvar::SysvarId; // For SLOTHASHES_ID
             use std::cell::RefCell;
             use std::rc::Rc;

             let key = SLOTHASHES_ID;
             let mut lamports = 0;
             let owner = Pubkey::new_unique(); // Mock owner

             // Case 1: Valid data
             let mock_entries = [(100, [1u8; HASH_BYTES])];
             let mut data = create_mock_data(&mock_entries);
             let account_info_ok = AccountInfo {
                 key: &key,
                 is_signer: false,
                 is_writable: false,
                 lamports: Rc::new(RefCell::new(&mut lamports)),
                 data: Rc::new(RefCell::new(&mut data)),
                 owner: &owner,
                 executable: false,
                 rent_epoch: 0,
             };
             let slot_hashes_res = SlotHashes::from_account_info(&account_info_ok);
             assert!(slot_hashes_res.is_ok());
             let slot_hashes = slot_hashes_res.unwrap();
             assert_eq!(slot_hashes.len(), 1);
             assert_eq!(slot_hashes.get_entry(0).unwrap().slot, 100);

             // Case 2: Invalid Key
             let wrong_key = Pubkey::new_unique();
             let account_info_wrong_key = AccountInfo { key: &wrong_key, ..account_info_ok.clone() };
             let res_wrong_key = SlotHashes::from_account_info(&account_info_wrong_key);
             assert!(matches!(res_wrong_key, Err(ProgramError::InvalidArgument)));
             
             // Case 3: Data too small
             let mut short_data = vec![0u8; 4]; // Less than NUM_ENTRIES_SIZE
             let account_info_short = AccountInfo { data: Rc::new(RefCell::new(&mut short_data)), ..account_info_ok.clone() };
             let res_short = SlotHashes::from_account_info(&account_info_short);
             assert!(matches!(res_short, Err(ProgramError::AccountDataTooSmall)));
             
             // Case 4: Invalid data (length mismatch)
             let mut invalid_data = create_mock_data(&mock_entries);
             invalid_data.truncate(NUM_ENTRIES_SIZE + ENTRY_SIZE - 1); // Not enough for declared entry
             let account_info_invalid = AccountInfo { data: Rc::new(RefCell::new(&mut invalid_data)), ..account_info_ok.clone() };
             let res_invalid = SlotHashes::from_account_info(&account_info_invalid);
             assert!(matches!(res_invalid, Err(ProgramError::InvalidAccountData)));

            // Case 5: Borrow fail (already borrowed mutably elsewhere - simulated)
            // This is harder to directly test without more complex mocking or real runtime
            // let _borrow = account_info_ok.data.borrow_mut(); 
            // let res_borrow_fail = SlotHashes::from_account_info(&account_info_ok);
            // assert!(matches!(res_borrow_fail, Err(ProgramError::AccountBorrowFailed)));
            // Drop the borrow explicitly if tested: drop(_borrow); 
        }

        #[test]
        fn test_binary_search_and_linear() {
            // Use the generic struct directly with a slice for testing
            // No need for the previous MockSlotHashes struct
            
            // Test data
            let entries_data = vec![
                SlotHashEntry { slot: 100, hash: [1u8; HASH_BYTES] },
                SlotHashEntry { slot: 98, hash: [2u8; HASH_BYTES] },
                SlotHashEntry { slot: 95, hash: [3u8; HASH_BYTES] },
                SlotHashEntry { slot: 90, hash: [4u8; HASH_BYTES] },
                SlotHashEntry { slot: 85, hash: [5u8; HASH_BYTES] },
            ];
            let mock_data = create_mock_data(&entries_data.iter().map(|e| (e.slot, e.hash)).collect::<Vec<_>>());
            let count = entries_data.len();
            let slot_hashes = unsafe { SlotHashes::new_unchecked(mock_data.as_slice(), count) };
            
            // Test binary search position
            assert_eq!(slot_hashes.position(100), Some(0));
            assert_eq!(slot_hashes.position(98), Some(1));
            assert_eq!(slot_hashes.position(95), Some(2));
            assert_eq!(slot_hashes.position(90), Some(3));
            assert_eq!(slot_hashes.position(85), Some(4));
            assert_eq!(slot_hashes.position(99), None);
            assert_eq!(slot_hashes.position(84), None);
            
            // Test standard binary search position
            assert_eq!(slot_hashes.position_standard(100), Some(0));
            assert_eq!(slot_hashes.position_standard(98), Some(1));
            assert_eq!(slot_hashes.position_standard(95), Some(2));
            assert_eq!(slot_hashes.position_standard(90), Some(3));
            assert_eq!(slot_hashes.position_standard(85), Some(4));
            assert_eq!(slot_hashes.position_standard(99), None);
            assert_eq!(slot_hashes.position_standard(84), None);
            
            // Test binary search get_hash
            assert_eq!(slot_hashes.get_hash(100), Some(&[1u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash(98), Some(&[2u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash(85), Some(&[5u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash(99), None);
            assert_eq!(slot_hashes.get_hash(101), None);
            assert_eq!(slot_hashes.get_hash(84), None);
            
            // Test standard binary search get_hash
            assert_eq!(slot_hashes.get_hash_standard(100), Some(&[1u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash_standard(98), Some(&[2u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash_standard(85), Some(&[5u8; HASH_BYTES]));
            assert_eq!(slot_hashes.get_hash_standard(99), None);
            assert_eq!(slot_hashes.get_hash_standard(101), None);
            assert_eq!(slot_hashes.get_hash_standard(84), None);
            
            // Test empty
            let empty_data = create_mock_data(&[]);
            let empty_hashes = unsafe { SlotHashes::new_unchecked(empty_data.as_slice(), 0) };
            assert_eq!(empty_hashes.position(100), None);
            assert_eq!(empty_hashes.position_standard(100), None);
            assert_eq!(empty_hashes.get_hash(100), None);
            assert_eq!(empty_hashes.get_hash_standard(100), None);
        }
    }
    
    // No-std compatible version of binary search test using arrays
    #[test]
    fn test_binary_search_no_std() {
        // Use the generic struct with a slice reference
        let entries: &[(Slot, [u8; HASH_BYTES])] = &[
            (100, [1u8; HASH_BYTES]),
            (98, [2u8; HASH_BYTES]),
            (95, [3u8; HASH_BYTES]),
            (90, [4u8; HASH_BYTES]),
            (85, [5u8; HASH_BYTES]),
        ];
        
        // Create mock sysvar data structure (length + entries)
        let num_entries_bytes = (entries.len() as u64).to_le_bytes();
        // Use a const generic for the array size based on the test data
        const TEST_LEN: usize = 5;
        let mut raw_data = [0u8; NUM_ENTRIES_SIZE + TEST_LEN * ENTRY_SIZE]; // Fixed size buffer
        raw_data[..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries_bytes);
        let mut cursor = NUM_ENTRIES_SIZE;
        for (slot, hash) in entries {
            raw_data[cursor..cursor+SLOT_SIZE].copy_from_slice(&slot.to_le_bytes());
            cursor += SLOT_SIZE;
            raw_data[cursor..cursor+HASH_BYTES].copy_from_slice(hash);
            cursor += HASH_BYTES;
        }
        
        // Create SlotHashes using the unsafe constructor with a slice
        let slot_hashes = unsafe {
            SlotHashes::new_unchecked(&raw_data[..cursor], entries.len())
        };

        // Test the binary search algorithm
        assert_eq!(slot_hashes.position(100), Some(0));
        assert_eq!(slot_hashes.position(98), Some(1));
        assert_eq!(slot_hashes.position(95), Some(2));
        assert_eq!(slot_hashes.position(90), Some(3));
        assert_eq!(slot_hashes.position(85), Some(4));
        
        // Test non-existent slots
        assert_eq!(slot_hashes.position(99), None);
        assert_eq!(slot_hashes.position(101), None);
        assert_eq!(slot_hashes.position(84), None);
        
        // Test get_hash on main list
        assert_eq!(slot_hashes.get_hash(100), Some(&[1u8; HASH_BYTES])); // First
        assert_eq!(slot_hashes.get_hash(95), Some(&[3u8; HASH_BYTES])); // Middle
        assert_eq!(slot_hashes.get_hash(85), Some(&[5u8; HASH_BYTES])); // Last
        assert_eq!(slot_hashes.get_hash(99), None); // Between
        assert_eq!(slot_hashes.get_hash(101), None); // > Max
        assert_eq!(slot_hashes.get_hash(84), None); // < Min
        
        // Test get_hash_standard on main list
        assert_eq!(slot_hashes.get_hash_standard(100), Some(&[1u8; HASH_BYTES])); // First
        assert_eq!(slot_hashes.get_hash_standard(95), Some(&[3u8; HASH_BYTES])); // Middle
        assert_eq!(slot_hashes.get_hash_standard(85), Some(&[5u8; HASH_BYTES])); // Last
        assert_eq!(slot_hashes.get_hash_standard(99), None); // Between
        assert_eq!(slot_hashes.get_hash_standard(101), None); // > Max
        assert_eq!(slot_hashes.get_hash_standard(84), None); // < Min

        // Test with smaller array (create new raw_data)
        let single_entry: &[(Slot, [u8; HASH_BYTES])] = &[(100, [1u8; HASH_BYTES])];
        let num_entries_bytes_1 = (single_entry.len() as u64).to_le_bytes();
        const TEST_LEN_1: usize = 1;
        let mut raw_data_1 = [0u8; NUM_ENTRIES_SIZE + TEST_LEN_1 * ENTRY_SIZE];
        raw_data_1[..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries_bytes_1);
        raw_data_1[NUM_ENTRIES_SIZE..NUM_ENTRIES_SIZE+SLOT_SIZE].copy_from_slice(&single_entry[0].0.to_le_bytes());
        raw_data_1[NUM_ENTRIES_SIZE+SLOT_SIZE..].copy_from_slice(&single_entry[0].1);
        
        let small_mock = unsafe {
            SlotHashes::new_unchecked(&raw_data_1[..NUM_ENTRIES_SIZE + ENTRY_SIZE], 1)
        };
        
        assert_eq!(small_mock.position(100), Some(0));
        assert_eq!(small_mock.position(99), None);
        // Test get_hash on single-entry list
        assert_eq!(small_mock.get_hash(100), Some(&[1u8; HASH_BYTES])); 
        assert_eq!(small_mock.get_hash(99), None);
        // Test get_hash_standard on single-entry list
        assert_eq!(small_mock.get_hash_standard(100), Some(&[1u8; HASH_BYTES]));
        assert_eq!(small_mock.get_hash_standard(99), None);

        // Test empty list explicitly for get_hash
        let empty_num_bytes = (0u64).to_le_bytes();
        let mut empty_raw_data = [0u8; NUM_ENTRIES_SIZE];
        empty_raw_data[..NUM_ENTRIES_SIZE].copy_from_slice(&empty_num_bytes);
        let empty_hashes = unsafe { SlotHashes::new_unchecked(&empty_raw_data[..], 0) };
        assert_eq!(empty_hashes.get_hash(100), None);
        assert_eq!(empty_hashes.get_hash_standard(100), None);
    }

    // No-std compatible tests
    #[test]
    fn test_basic_getters_and_iterator_no_std() {
        // Mock data setup similar to test_binary_search_no_std
        let entries: &[(Slot, [u8; HASH_BYTES])] = &[
            (100, [1u8; HASH_BYTES]),
            (98, [2u8; HASH_BYTES]),
            (95, [3u8; HASH_BYTES]),
        ];
        let num_entries_bytes = (entries.len() as u64).to_le_bytes();
        const TEST_LEN: usize = 3;
        let mut raw_data = [0u8; NUM_ENTRIES_SIZE + TEST_LEN * ENTRY_SIZE]; 
        raw_data[..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries_bytes);
        let mut cursor = NUM_ENTRIES_SIZE;
        for (slot, hash) in entries {
            raw_data[cursor..cursor+SLOT_SIZE].copy_from_slice(&slot.to_le_bytes());
            cursor += SLOT_SIZE;
            raw_data[cursor..cursor+HASH_BYTES].copy_from_slice(hash);
            cursor += HASH_BYTES;
        }
        let data_slice = &raw_data[..cursor]; // Slice of the populated part
        let slot_hashes = unsafe { SlotHashes::new_unchecked(data_slice, entries.len()) };

        // Test len() and is_empty()
        assert_eq!(slot_hashes.len(), 3);
        assert!(!slot_hashes.is_empty());

        // Test get_entry()
        let entry0 = slot_hashes.get_entry(0);
        assert!(entry0.is_some());
        assert_eq!(entry0.unwrap().slot, 100);
        assert_eq!(entry0.unwrap().hash, [1u8; HASH_BYTES]);
        let entry2 = slot_hashes.get_entry(2);
        assert!(entry2.is_some());
        assert_eq!(entry2.unwrap().slot, 95);
        assert_eq!(entry2.unwrap().hash, [3u8; HASH_BYTES]);
        assert!(slot_hashes.get_entry(3).is_none()); // Out of bounds

        // Test iterator
        let mut iter = slot_hashes.into_iter();
        assert_eq!(iter.next().unwrap().slot, 100);
        assert_eq!(iter.next().unwrap().slot, 98);
        assert_eq!(iter.next().unwrap().slot, 95);
        assert!(iter.next().is_none());

        // Test ExactSizeIterator hint
        let mut iter_hint = slot_hashes.into_iter();
        assert_eq!(iter_hint.size_hint(), (3, Some(3)));
        iter_hint.next();
        assert_eq!(iter_hint.size_hint(), (2, Some(2)));

        // Test empty case
        let empty_num_bytes = (0u64).to_le_bytes();
        let mut empty_raw_data = [0u8; NUM_ENTRIES_SIZE];
        empty_raw_data[..NUM_ENTRIES_SIZE].copy_from_slice(&empty_num_bytes);
        let empty_hashes = unsafe { SlotHashes::new_unchecked(&empty_raw_data[..], 0) };
        assert_eq!(empty_hashes.len(), 0);
        assert!(empty_hashes.is_empty());
        assert!(empty_hashes.get_entry(0).is_none());
        assert!(empty_hashes.into_iter().next().is_none());
    }

    #[test]
    fn test_from_bytes_no_std() {
        // Valid data (2 entries)
        let entries: &[(Slot, [u8; HASH_BYTES])] = &[
            (100, [1u8; HASH_BYTES]),
            (98, [2u8; HASH_BYTES]),
        ];
        let num_entries_bytes = (entries.len() as u64).to_le_bytes();
        const TEST_LEN: usize = 2;
        let mut raw_data = [0u8; NUM_ENTRIES_SIZE + TEST_LEN * ENTRY_SIZE];
        raw_data[..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries_bytes);
        let mut cursor = NUM_ENTRIES_SIZE;
        for (slot, hash) in entries {
            raw_data[cursor..cursor+SLOT_SIZE].copy_from_slice(&slot.to_le_bytes());
            cursor += SLOT_SIZE;
            raw_data[cursor..cursor+HASH_BYTES].copy_from_slice(hash);
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
        let empty_res = SlotHashes::<&[u8]>::from_bytes(&empty_raw_data[..]);
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
         raw_data_1[NUM_ENTRIES_SIZE..NUM_ENTRIES_SIZE+SLOT_SIZE].copy_from_slice(&single_entry[0].0.to_le_bytes());
         raw_data_1[NUM_ENTRIES_SIZE+SLOT_SIZE..].copy_from_slice(&single_entry[0].1);
         let slot_hashes = unsafe { SlotHashes::new_unchecked(&raw_data_1[..], 1) };

         // Safety: index 0 is valid because len is 1
         let entry = unsafe { slot_hashes.get_entry_unchecked(0) };
         assert_eq!(entry.slot, 100);
         assert_eq!(entry.hash, [1u8; HASH_BYTES]);
    }
    
    // No-std compatible version of binary search test using arrays
    // ... existing code ...
}
