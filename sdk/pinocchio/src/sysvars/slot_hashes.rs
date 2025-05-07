//! Efficient, zero-copy access to SlotHashes sysvar data.

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
    len: usize,
}

impl<T> SlotHashes<T>
where
    T: Deref<Target = [u8]>,
{
    /// Creates a `SlotHashes` instance directly from a data container and entry count.
    /// Important: provide a valid len. Whether or not len is assumed to be
    /// the constant 20_488 (512 entries) is up to caller.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it does not check the validity of the data or count.
    /// The caller must ensure:
    /// 1. The underlying byte slice in `data` represents valid SlotHashes data
    ///    (length prefix + entries).
    /// 2. `len` is the correct number of entries (≤ MAX_ENTRIES), matching the prefix.
    /// 3. The data slice contains at least `NUM_ENTRIES_SIZE + len * ENTRY_SIZE` bytes.
    /// 4. If `T` is `&[u8]`, that borrow rules are upheld.
    /// 5. Alignment is correct.
    ///
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
            return Err(ProgramError::InvalidAccountData);
        }

        Ok((num_entries_usize, required_len))
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
        num_entries as usize
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
    /// Returns `None` if the index is out of bounds.
    #[inline(always)]
    pub fn get_entry(&self, index: usize) -> Option<&SlotHashEntry> {
        if index >= self.len {
            return None;
        }

        let start = NUM_ENTRIES_SIZE + index * ENTRY_SIZE;
        let end = start + ENTRY_SIZE;

        // Safety bounds check
        let entry_bytes = self.data.get(start..end)?;
        // Safety: constructor guarantees data layout & alignment
        Some(unsafe { &*(entry_bytes.as_ptr() as *const SlotHashEntry) })
    }

    /// Gets a reference without bounds checking.
    ///
    /// # Safety
    /// Caller must ensure `index < self.len()`.
    #[inline(always)]
    pub unsafe fn get_entry_unchecked(&self, index: usize) -> &SlotHashEntry {
        debug_assert!(index < self.len);
        let offset = NUM_ENTRIES_SIZE + index * ENTRY_SIZE;
        &*(self.data.as_ptr().add(offset) as *const SlotHashEntry)
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
    fn interpolated_binary_search_slot(&self, target_slot: Slot) -> Option<usize> {
        // Safety: self.len is trusted. get_entry_unchecked is safe if index < self.len.
        // The core_interpolated_search logic respects num_entries (self.len here) for bounds.
        unsafe {
            core_interpolated_search(
                target_slot,
                self.len,
                || {
                    // Assumes self.len > 0, which core_interpolated_search checks via num_entries.
                    // If self.len is 0, this closure won't be called.
                    self.get_entry_unchecked(0).slot
                },
                |idx| {
                    // The index `idx` comes from core_interpolated_search's `probe_idx`,
                    // which is clamped to be `< num_entries` (i.e., `< self.len`).
                    self.get_entry_unchecked(idx).slot
                },
            )
        }
    }

    /// Finds the hash for a specific slot using domain-aware binary search.
    ///
    /// Returns the hash if the slot is found, or `None` if not found.
    /// Assumes entries are sorted by slot in descending order.
    #[inline(always)]
    pub fn get_hash(&self, target_slot: Slot) -> Option<&[u8; HASH_BYTES]> {
        self.interpolated_binary_search_slot(target_slot)
            .and_then(|idx| self.get_entry(idx))
            .map(|entry| &entry.hash)
    }

    /// Finds the position (index) of a specific slot using domain-aware binary search.
    ///
    /// Returns the index if the slot is found, or `None` if not found.
    /// Assumes entries are sorted by slot in descending order.
    #[inline(always)]
    pub fn position(&self, target_slot: Slot) -> Option<usize> {
        self.interpolated_binary_search_slot(target_slot)
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
        let (num_entries, _) = Self::parse_and_validate_data(&data_ref)?;

        // Construct using the unsafe constructor, providing the validated Ref and count
        // Safety: We performed the necessary checks above.
        Ok(unsafe { Self::new_unchecked(data_ref, num_entries) })
    }
}

/// Reads the entry count directly from the beginning of a byte slice **without validation**.
/// (This is identical to the struct method get_entry_count_unchecked,
/// added here for discoverability with other unchecked fns)
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
pub unsafe fn get_entry_count_from_slice_unchecked(data: &[u8]) -> usize {
    // Safety: assumes data has at least NUM_ENTRIES_SIZE bytes.
    let len_bytes: [u8; NUM_ENTRIES_SIZE] = data
        .get_unchecked(0..NUM_ENTRIES_SIZE)
        .try_into()
        .unwrap_unchecked();
    let num_entries = u64::from_le_bytes(len_bytes);
    num_entries as usize
}

/// Performs an **unsafe** interpolation binary search directly on a raw byte slice.
///
/// # Safety
/// Caller must guarantee `data` contains a valid `SlotHashes` structure and that
/// `num_entries` is the correct count of entries in `data`. It is up to caller whether
/// to use MAX_ENTRIES or to use a call such as `get_entry_count_from_slice_unchecked`
#[inline(always)]
pub unsafe fn position_from_slice_unchecked(
    data: &[u8],
    target_slot: Slot,
    num_entries: usize,
) -> Option<usize> {
    // Safety: Caller guarantees num_entries and data validity.
    // Closures perform unchecked access, relying on these guarantees and
    // on core_interpolated_search respecting num_entries for bounds.
    core_interpolated_search(
        target_slot,
        num_entries,
        || {
            // Assumes num_entries > 0, which core_interpolated_search checks.
            // If num_entries is 0, this closure won't be called.
            u64::from_le_bytes(
                data.get_unchecked(NUM_ENTRIES_SIZE..NUM_ENTRIES_SIZE + SLOT_SIZE)
                    .try_into()
                    .unwrap_unchecked(),
            )
        },
        |idx| {
            // The index `idx` comes from core_interpolated_search's `probe_idx`,
            // which is clamped to be `< num_entries`.
            let entry_offset = NUM_ENTRIES_SIZE + idx * ENTRY_SIZE;
            let entry_bytes = data.get_unchecked(entry_offset..(entry_offset + ENTRY_SIZE));
            u64::from_le_bytes(
                entry_bytes
                    .get_unchecked(0..SLOT_SIZE)
                    .try_into()
                    .unwrap_unchecked(),
            )
        },
    )
}

/// Gets a reference to the hash for a specific slot from a raw byte slice **without validation**.
///
/// # Safety
/// Caller must guarantee `data` contains a valid `SlotHashes` structure.
/// Caller must guarantee `num_entries` is the correct count of entries in `data`. It is up
/// to caller whether to use MAX_ENTRIES or to use a call such as `get_entry_count_from_slice_unchecked`
#[inline(always)]
pub unsafe fn get_hash_from_slice_unchecked(
    data: &[u8],
    target_slot: Slot,
    num_entries: usize,
) -> Option<&[u8; HASH_BYTES]> {
    position_from_slice_unchecked(data, target_slot, num_entries).map(|index| {
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
// TODO: trait extension for unchecked Iterator::next()
impl<'s, T> Iterator for SlotHashesIterator<'s, T>
where
    T: Deref<Target = [u8]>,
{
    type Item = &'s SlotHashEntry;

    fn next(&mut self) -> Option<Self::Item> {
        // Use safe get_entry method from SlotHashes
        let entry = self.slot_hashes.get_entry(self.current_index);
        if entry.is_some() {
            self.current_index += 1;
        }
        entry
    }

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

#[inline(always)]
unsafe fn core_interpolated_search<FFirstSlot, FSlotAtIndex>(
    target_slot: Slot,
    num_entries: usize,
    get_first_slot: FFirstSlot,
    get_slot_at_index: FSlotAtIndex,
) -> Option<usize>
where
    FFirstSlot: FnOnce() -> Slot,
    FSlotAtIndex: Fn(usize) -> Slot,
{
    if num_entries == 0 {
        return None;
    }
    let first_slot = get_first_slot();
    if target_slot > first_slot {
        return None;
    }
    if target_slot == first_slot {
        return Some(0);
    }

    let mut low = 0;
    let mut high = num_entries;

    while low < high {
        let delta_slots = first_slot.saturating_sub(target_slot);
        // Heuristic: estimate index assuming average gap of ~5% (1/20 reduction per slot_diff)
        let estimated_index = ((delta_slots.saturating_mul(19)) / 20) as usize;

        // Clamp the estimated index to be within [low, high - 1] to get our probe point.
        // Prevents the heuristic from going out of bounds.
        let probe_idx = estimated_index.clamp(low, high.saturating_sub(1));

        let entry_slot = get_slot_at_index(probe_idx);

        match entry_slot.cmp(&target_slot) {
            core::cmp::Ordering::Equal => return Some(probe_idx),
            core::cmp::Ordering::Greater => {
                // entry_slot at probe_idx is > target_slot. Target is further down (higher index).
                let slot_diff = entry_slot - target_slot;
                let max_possible_index_for_target = probe_idx.saturating_add(slot_diff as usize);
                low = probe_idx + 1;
                high = high.min(max_possible_index_for_target.saturating_add(1));
            }
            core::cmp::Ordering::Less => {
                // entry_slot at probe_idx is < target_slot. Target is further up (lower index).
                let slot_diff = target_slot - entry_slot;
                let min_possible_index_for_target = probe_idx.saturating_sub(slot_diff as usize);
                high = probe_idx;
                low = low.max(min_possible_index_for_target);
            }
        }
        if low >= high {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};
    extern crate std;
    #[allow(unused_imports)]
    use std::vec::Vec;

    #[test]
    fn test_layout_constants() {
        assert_eq!(NUM_ENTRIES_SIZE, size_of::<u64>());
        assert_eq!(SLOT_SIZE, size_of::<u64>());
        assert_eq!(HASH_BYTES, 32);
        assert_eq!(ENTRY_SIZE, size_of::<u64>() + 32);
        assert_eq!(size_of::<SlotHashEntry>(), ENTRY_SIZE);
        assert_eq!(align_of::<SlotHashEntry>(), align_of::<u64>());
        assert_eq!(
            SLOTHASHES_ID,
            [
                6, 167, 213, 23, 25, 47, 10, 175, 198, 242, 101, 227, 251, 119, 204, 122, 218, 130,
                197, 41, 208, 190, 59, 19, 110, 45, 0, 85, 32, 0, 0, 0,
            ]
        );
        const BASE_58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        // quick base58 comparison just for test
        pub fn check_base58(input_bytes: &[u8], expected_b58: &str) {
            let mut b58_digits_rev = std::vec![0u8];
            for &byte_val in input_bytes {
                let mut carry = byte_val as u32;
                for digit_ref in b58_digits_rev.iter_mut() {
                    let temp_val = ((*digit_ref as u32) << 8) | carry;
                    *digit_ref = (temp_val % 58) as u8;
                    carry = temp_val / 58;
                }
                while carry > 0 {
                    b58_digits_rev.push((carry % 58) as u8);
                    carry /= 58;
                }
            }
            for &byte_val in input_bytes {
                if byte_val == 0 {
                    b58_digits_rev.push(0)
                } else {
                    break;
                }
            }
            let mut output_chars = Vec::with_capacity(b58_digits_rev.len());
            for &digit_val in b58_digits_rev.iter().rev() {
                output_chars.push(BASE_58[digit_val as usize]);
            }
            assert_eq!(expected_b58.as_bytes(), output_chars.as_slice());
        }
        check_base58(
            &SLOTHASHES_ID,
            "SysvarS1otHashes111111111111111111111111111",
        );
    }

    fn create_mock_data(entries: &[(u64, [u8; 32])]) -> Vec<u8> {
        let num_entries = entries.len() as u64;
        let data_len = NUM_ENTRIES_SIZE + entries.len() * ENTRY_SIZE;
        let mut data = std::vec![0u8; data_len];
        data[0..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries.to_le_bytes());
        let mut offset = NUM_ENTRIES_SIZE;
        for (slot, hash) in entries {
            data[offset..offset + SLOT_SIZE].copy_from_slice(&slot.to_le_bytes());
            data[offset + SLOT_SIZE..offset + ENTRY_SIZE].copy_from_slice(hash);
            offset += ENTRY_SIZE;
        }
        data
    }

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
                #[allow(dead_code)] // May be used by benchmarks
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

    #[cfg(feature = "std")]
    mod std_tests {
        use super::*;

        #[test]
        fn test_get_entry_count_logic() {
            let mock_entries = generate_mock_entries(3, 100, DecrementStrategy::Strictly1);
            let data = create_mock_data(&mock_entries);

            // Test the safe count getter
            let result = SlotHashes::<&[u8]>::get_entry_count(&data);
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
            const NUM_ENTRIES: usize = 512;
            const START_SLOT: u64 = 2000;
            let mock_entries =
                generate_mock_entries(NUM_ENTRIES, START_SLOT, DecrementStrategy::Average1_05);
            let mock_data = create_mock_data(&mock_entries);
            let count = mock_entries.len();
            let slot_hashes = unsafe { SlotHashes::new_unchecked(mock_data.as_slice(), count) };

            let first_slot = mock_entries[0].0;
            let last_slot = mock_entries[NUM_ENTRIES - 1].0;
            let mid_slot = mock_entries[NUM_ENTRIES / 2].0;

            // Test position
            assert_eq!(slot_hashes.position(first_slot), Some(0));
            assert_eq!(slot_hashes.position(mid_slot), Some(NUM_ENTRIES / 2));
            assert_eq!(slot_hashes.position(last_slot), Some(NUM_ENTRIES - 1));

            // Find a gap between consecutive slots to test non-existent slot search
            let missing_internal_slot = (0..mock_entries.len() - 1)
                .find(|&i| mock_entries[i].0 > mock_entries[i + 1].0 + 1)
                .map(|i| mock_entries[i + 1].0 + 1);

            assert!(
                missing_internal_slot.is_some(),
                "Average1_05 strategy should create gaps between slots"
            );
            assert_eq!(
                slot_hashes.position(missing_internal_slot.unwrap()),
                None,
                "Search should fail for slot {} between {} and {}",
                missing_internal_slot.unwrap(),
                mock_entries[0].0,
                mock_entries[mock_entries.len() - 1].0
            );

            // Test get_hash
            assert_eq!(slot_hashes.get_hash(first_slot), Some(&mock_entries[0].1));
            assert_eq!(
                slot_hashes.get_hash(mid_slot),
                Some(&mock_entries[NUM_ENTRIES / 2].1)
            );
            assert_eq!(slot_hashes.get_hash(START_SLOT + 1), None);

            // Test empty
            let empty_data = create_mock_data(&[]);
            let empty_hashes = unsafe { SlotHashes::new_unchecked(empty_data.as_slice(), 0) };
            assert_eq!(empty_hashes.position(100), None);
        }

        #[test]
        fn test_basic_getters_and_iterator() {
            const NUM_ENTRIES: usize = 512;
            const START_SLOT: u64 = 2000;
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
            // Use enumerate to avoid clippy lint about indexing
            for (i, entry) in slot_hashes.into_iter().enumerate() {
                assert_eq!(entry.slot, mock_entries[i].0);
                assert_eq!(entry.hash, mock_entries[i].1);
            }
            // Check that the iterator is exhausted
            assert!(slot_hashes.into_iter().nth(NUM_ENTRIES).is_none());

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
        fn test_entry_count() {
            let mock_entries = generate_mock_entries(2, 100, DecrementStrategy::Strictly1);
            let data = create_mock_data(&mock_entries);

            // Valid data
            let count_res = SlotHashes::<&[u8]>::get_entry_count(&data);
            assert!(count_res.is_ok());
            assert_eq!(count_res.unwrap(), 2);

            // Data too small (less than len prefix)
            let short_data_1 = &data[0..NUM_ENTRIES_SIZE - 1];
            let res1 = SlotHashes::<&[u8]>::get_entry_count(short_data_1);
            assert!(matches!(res1, Err(ProgramError::AccountDataTooSmall)));

            // Data too small (correct len prefix, but not enough data for entries)
            let short_data_2 = &data[0..NUM_ENTRIES_SIZE + ENTRY_SIZE]; // Only space for 1 entry
            let res2 = SlotHashes::<&[u8]>::get_entry_count(short_data_2);
            assert!(matches!(res2, Err(ProgramError::InvalidAccountData)));
            let count_res_unchecked_2 =
                unsafe { SlotHashes::<&[u8]>::get_entry_count_unchecked(short_data_2) };
            assert_eq!(count_res_unchecked_2, 2);

            // Empty data is valid
            let empty_data = create_mock_data(&[]);
            let empty_res = SlotHashes::<&[u8]>::get_entry_count(&empty_data);
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
            const NUM_ENTRIES: usize = 512;
            const START_SLOT: u64 = 2000;
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
                assert_eq!(get_entry_count_from_slice_unchecked(&data), NUM_ENTRIES);

                // Test position_from_slice_unchecked
                assert_eq!(
                    position_from_slice_unchecked(&data, first_slot, NUM_ENTRIES),
                    Some(0)
                );
                assert_eq!(
                    position_from_slice_unchecked(&data, mid_slot, NUM_ENTRIES),
                    Some(mid_index)
                );
                assert_eq!(
                    position_from_slice_unchecked(&data, last_slot, NUM_ENTRIES),
                    Some(NUM_ENTRIES - 1)
                );
                assert_eq!(
                    position_from_slice_unchecked(&data, missing_slot_high, NUM_ENTRIES),
                    None
                );
                assert_eq!(
                    position_from_slice_unchecked(&data, missing_slot_low, NUM_ENTRIES),
                    None
                );

                // Test get_hash_from_slice_unchecked
                assert_eq!(
                    get_hash_from_slice_unchecked(&data, first_slot, NUM_ENTRIES),
                    Some(&mock_entries[0].1)
                );
                assert_eq!(
                    get_hash_from_slice_unchecked(&data, mid_slot, NUM_ENTRIES),
                    Some(&mock_entries[mid_index].1)
                );
                assert_eq!(
                    get_hash_from_slice_unchecked(&data, last_slot, NUM_ENTRIES),
                    Some(&mock_entries[NUM_ENTRIES - 1].1)
                );
                assert_eq!(
                    get_hash_from_slice_unchecked(&data, missing_slot_high, NUM_ENTRIES),
                    None
                );
                assert_eq!(
                    get_hash_from_slice_unchecked(&data, missing_slot_low, NUM_ENTRIES),
                    None
                );

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
                assert_eq!(get_entry_count_from_slice_unchecked(&empty_data), 0);
                assert_eq!(position_from_slice_unchecked(&empty_data, 100, 0), None);
                assert_eq!(get_hash_from_slice_unchecked(&empty_data, 100, 0), None);
                // Calling get_entry_from_slice_unchecked with index 0 on empty data is UB, not tested.
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    #[allow(dead_code)]
    enum DecrementStrategy {
        Strictly1,
        Average1_05,
        Average2,
    }

    // Stand-in for proper fuzz (todo)
    fn simple_prng(seed: u64) -> u64 {
        const A: u64 = 16807;
        const M: u64 = 2147483647;
        let initial_state = if seed == 0 { 1 } else { seed };
        (A.wrapping_mul(initial_state)) % M
    }

    #[test]
    fn test_binary_search_no_std() {
        const TEST_NUM_ENTRIES: usize = 512;
        const START_SLOT: u64 = 2000;

        // Generate entries using Avg1.05 strategy
        let entries =
            generate_mock_entries(TEST_NUM_ENTRIES, START_SLOT, DecrementStrategy::Average1_05);
        let data = create_mock_data(&entries);
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

        let expected_mid_index = Some(mid_index);
        let actual_pos_mid = slot_hashes.position(mid_slot);

        // Extract surrounding entries for context in case of failure
        let start_idx = mid_index.saturating_sub(2);
        let end_idx = core::cmp::min(entry_count, mid_index.saturating_add(3));
        let surrounding_slots: Vec<_> = entries[start_idx..end_idx].iter().map(|e| e.0).collect();
        assert_eq!(
            actual_pos_mid, expected_mid_index,
            "position({}) failed! Surrounding slots: {:?}",
            mid_slot, surrounding_slots
        );

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
        assert!(
            missing_internal_slot.is_some(),
            "Test requires at least one gap between slots"
        );
        assert_eq!(slot_hashes.position(missing_internal_slot.unwrap()), None);

        // Test get_hash (interpolation)
        assert_eq!(slot_hashes.get_hash(first_slot), Some(&entries[0].1));
        assert_eq!(slot_hashes.get_hash(mid_slot), Some(&entries[mid_index].1));
        assert_eq!(
            slot_hashes.get_hash(last_slot),
            Some(&entries[entry_count - 1].1)
        );
        assert_eq!(slot_hashes.get_hash(START_SLOT + 1), None);

        // Test empty list explicitly
        let empty_entries = generate_mock_entries(0, START_SLOT, DecrementStrategy::Strictly1);
        let empty_data = create_mock_data(&empty_entries);
        let empty_hashes = unsafe { SlotHashes::new_unchecked(empty_data.as_slice(), 0) };
        assert_eq!(empty_hashes.get_hash(100), None);

        let pos_start_plus_1 = slot_hashes.position(START_SLOT + 1);
        assert!(
            pos_start_plus_1.is_none(),
            "position(START_SLOT + 1) should be None"
        );
    }

    // No-std compatible tests
    #[test]
    fn test_basic_getters_and_iterator_no_std() {
        const NUM_ENTRIES: usize = 512;
        const START_SLOT: u64 = 2000;
        let entries = generate_mock_entries(NUM_ENTRIES, START_SLOT, DecrementStrategy::Strictly1);
        let data = create_mock_data(&entries);
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
        // Use enumerate to avoid clippy lint about indexing
        for (i, entry) in slot_hashes.into_iter().enumerate() {
            assert_eq!(entry.slot, entries[i].0);
            assert_eq!(entry.hash, entries[i].1);
        }
        // Check that the iterator is exhausted
        assert!(slot_hashes.into_iter().nth(NUM_ENTRIES).is_none());

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
    fn test_get_entry_count_no_std() {
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
        let count_res = SlotHashes::<&[u8]>::get_entry_count(data_slice);
        assert!(count_res.is_ok());
        assert_eq!(count_res.unwrap(), 2);
        let count_res_unchecked =
            unsafe { SlotHashes::<&[u8]>::get_entry_count_unchecked(data_slice) };
        assert_eq!(count_res_unchecked, 2);

        // Data too small (less than len prefix)
        let short_data_1 = &data_slice[0..NUM_ENTRIES_SIZE - 1];
        let res1 = SlotHashes::<&[u8]>::get_entry_count(short_data_1);
        assert!(matches!(res1, Err(ProgramError::AccountDataTooSmall)));

        // Data too small (correct len prefix, but not enough data for entries)
        let short_data_2 = &data_slice[0..NUM_ENTRIES_SIZE + ENTRY_SIZE]; // Only space for 1 entry
        let res2 = SlotHashes::<&[u8]>::get_entry_count(short_data_2);
        assert!(matches!(res2, Err(ProgramError::InvalidAccountData)));
        let count_res_unchecked_2 =
            unsafe { SlotHashes::<&[u8]>::get_entry_count_unchecked(short_data_2) };
        assert_eq!(count_res_unchecked_2, 2);

        // Empty data is valid
        let empty_num_bytes = (0u64).to_le_bytes();
        let mut empty_raw_data = [0u8; NUM_ENTRIES_SIZE];
        empty_raw_data[..NUM_ENTRIES_SIZE].copy_from_slice(&empty_num_bytes);
        let empty_res = SlotHashes::<&[u8]>::get_entry_count(empty_raw_data.as_slice());
        assert!(empty_res.is_ok());
        assert_eq!(empty_res.unwrap(), 0);
        let empty_res_unchecked =
            unsafe { SlotHashes::<&[u8]>::get_entry_count_unchecked(empty_raw_data.as_slice()) };
        assert_eq!(empty_res_unchecked, 0);
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
