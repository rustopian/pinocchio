//! Tests that rely on the `std` feature (host-only helpers, alloc, etc.).

use super::*;
use crate::{
    account_info::{Account, AccountInfo},
    pubkey::Pubkey,
};
use core::ptr;
extern crate std;
use std::io::Write;
use std::vec::Vec;

fn create_mock_data_max_size(entries: &[(u64, [u8; 32])]) -> Vec<u8> {
    let num_entries = entries.len() as u64;
    let mut data = std::vec![0u8; MAX_SIZE];
    data[0..NUM_ENTRIES_SIZE].copy_from_slice(&num_entries.to_le_bytes());
    let mut offset = NUM_ENTRIES_SIZE;
    for (slot, hash) in entries {
        data[offset..offset + SLOT_SIZE].copy_from_slice(&slot.to_le_bytes());
        data[offset + SLOT_SIZE..offset + ENTRY_SIZE].copy_from_slice(hash);
        offset += ENTRY_SIZE;
    }
    data
}

#[allow(dead_code)]
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

#[test]
fn test_from_account_info_constructor() {
    use std::eprintln;
    eprintln!("DEBUG: Test starting");
    std::io::stderr().flush().unwrap();

    const NUM_ENTRIES: usize = 3;
    const START_SLOT: u64 = 1234;

    let mock_entries = generate_mock_entries(NUM_ENTRIES, START_SLOT, DecrementStrategy::Strictly1);
    let data = create_mock_data_max_size(&mock_entries);

    let mut aligned_backing: Vec<u64>;
    #[allow(unused_assignments)]
    let mut acct_ptr: *mut Account = core::ptr::null_mut();

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FakeAccount {
        borrow_state: u8,
        is_signer: u8,
        is_writable: u8,
        executable: u8,
        resize_delta: i32,
        key: Pubkey,
        owner: Pubkey,
        lamports: u64,
        data_len: u64,
    }

    unsafe {
        let header_size = core::mem::size_of::<FakeAccount>();
        let total_size = header_size + data.len();
        let word_len = (total_size + 7) / 8;
        aligned_backing = std::vec![0u64; word_len];
        let base_ptr = aligned_backing.as_mut_ptr() as *mut u8;

        let header_ptr = base_ptr as *mut FakeAccount;
        ptr::write(
            header_ptr,
            FakeAccount {
                borrow_state: crate::NON_DUP_MARKER,
                is_signer: 0,
                is_writable: 0,
                executable: 0,
                resize_delta: 0,
                key: SLOTHASHES_ID,
                owner: [0u8; 32],
                lamports: 0,
                data_len: data.len() as u64,
            },
        );

        ptr::copy_nonoverlapping(data.as_ptr(), base_ptr.add(header_size), data.len());

        acct_ptr = base_ptr as *mut Account;
    }

    let account_info = AccountInfo { raw: acct_ptr };

    let slot_hashes = SlotHashes::from_account_info(&account_info)
        .expect("from_account_info should succeed with well-formed data");

    assert_eq!(slot_hashes.len(), NUM_ENTRIES);
    for (i, entry) in slot_hashes.into_iter().enumerate() {
        assert_eq!(entry.slot(), mock_entries[i].0);
        assert_eq!(entry.hash, mock_entries[i].1);
    }
}

#[cfg(feature = "std")]
#[test]
fn test_fetch_std_path() {
    const START_SLOT: u64 = 500;
    let entries = generate_mock_entries(5, START_SLOT, DecrementStrategy::Strictly1);
    let data = create_mock_data_max_size(&entries);

    let mut slot_hashes =
        SlotHashes::<std::boxed::Box<[u8]>>::fetch().expect("fetch() should succeed on host");

    slot_hashes.data[..data.len()].copy_from_slice(&data);

    assert_eq!(slot_hashes.len(), entries.len());
    for (i, entry) in slot_hashes.into_iter().enumerate() {
        assert_eq!(entry.slot(), entries[i].0);
        assert_eq!(entry.hash, entries[i].1);
    }
}
