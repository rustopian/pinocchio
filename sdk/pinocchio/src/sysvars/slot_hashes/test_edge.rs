use crate::{
    account_info::{Account, AccountInfo},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::slot_hashes::*,
};
use core::{mem, ptr};
extern crate std;
use std::vec::Vec;

fn raw_slot_hashes(declared_len: u64, entries: &[(u64, [u8; HASH_BYTES])]) -> Vec<u8> {
    let mut v = Vec::with_capacity(NUM_ENTRIES_SIZE + entries.len() * ENTRY_SIZE);
    v.extend_from_slice(&declared_len.to_le_bytes());
    for (slot, hash) in entries {
        v.extend_from_slice(&slot.to_le_bytes());
        v.extend_from_slice(hash);
    }
    v
}

struct AccountInfoWithBacking {
    info: AccountInfo,
    _backing: std::vec::Vec<u64>,
}

unsafe fn account_info_with(key: Pubkey, data: &[u8]) -> AccountInfoWithBacking {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Header {
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
    let hdr_len = mem::size_of::<Header>();
    let total = hdr_len + data.len();
    let words = (total + 7) / 8;
    let mut backing: std::vec::Vec<u64> = std::vec![0u64; words];
    let hdr_ptr = backing.as_mut_ptr() as *mut Header;
    ptr::write(
        hdr_ptr,
        Header {
            borrow_state: crate::NON_DUP_MARKER,
            is_signer: 0,
            is_writable: 0,
            executable: 0,
            resize_delta: 0,
            key,
            owner: [0u8; 32],
            lamports: 0,
            data_len: data.len() as u64,
        },
    );
    ptr::copy_nonoverlapping(data.as_ptr(), (hdr_ptr as *mut u8).add(hdr_len), data.len());
    AccountInfoWithBacking {
        info: AccountInfo {
            raw: hdr_ptr as *mut Account,
        },
        _backing: backing,
    }
}

unsafe fn account_info_with_borrow_state(
    key: Pubkey,
    data: &[u8],
    borrow_state: u8,
) -> AccountInfoWithBacking {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Header {
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
    let hdr_len = mem::size_of::<Header>();
    let total = hdr_len + data.len();
    let words = (total + 7) / 8;
    let mut backing: std::vec::Vec<u64> = std::vec![0u64; words];
    let hdr_ptr = backing.as_mut_ptr() as *mut Header;
    ptr::write(
        hdr_ptr,
        Header {
            borrow_state,
            is_signer: 0,
            is_writable: 0,
            executable: 0,
            resize_delta: 0,
            key,
            owner: [0u8; 32],
            lamports: 0,
            data_len: data.len() as u64,
        },
    );
    ptr::copy_nonoverlapping(data.as_ptr(), (hdr_ptr as *mut u8).add(hdr_len), data.len());
    AccountInfoWithBacking {
        info: AccountInfo {
            raw: hdr_ptr as *mut Account,
        },
        _backing: backing,
    }
}

#[test]
fn wrong_key_from_account_info() {
    let bytes = raw_slot_hashes(0, &[]);
    let acct_with = unsafe { account_info_with([1u8; 32], &bytes) };
    assert!(matches!(
        SlotHashes::from_account_info(&acct_with.info),
        Err(ProgramError::InvalidArgument)
    ));
}

#[test]
fn too_many_entries_rejected() {
    let bytes = raw_slot_hashes((MAX_ENTRIES as u64) + 1, &[]);
    assert!(matches!(
        SlotHashes::new(bytes.as_slice()),
        Err(ProgramError::InvalidArgument)
    ));
}

#[test]
fn truncated_payload_rejected() {
    let entry = (123u64, [7u8; HASH_BYTES]);
    let bytes = raw_slot_hashes(2, &[entry]); // says 2 but provides 1
    assert!(matches!(
        SlotHashes::new(bytes.as_slice()),
        Err(ProgramError::InvalidArgument)
    ));
}

#[test]
fn duplicate_slots_binary_search_safe() {
    let entries = &[
        (200, [0u8; HASH_BYTES]),
        (200, [1u8; HASH_BYTES]),
        (199, [2u8; HASH_BYTES]),
    ];
    let bytes = raw_slot_hashes(entries.len() as u64, entries);
    let sh = unsafe { SlotHashes::new_unchecked(&bytes[..], entries.len()) };
    let dup_pos = sh.position(200).expect("slot 200 must exist");
    assert!(
        dup_pos <= 1,
        "binary_search should return one of the duplicate indices (0 or 1)"
    );
    assert_eq!(sh.get_hash(199), Some(&entries[2].1));
}

#[test]
fn zero_len_minimal_slice_iterates_empty() {
    let zero_bytes = 0u64.to_le_bytes();
    let sh = unsafe { SlotHashes::new_unchecked(&zero_bytes[..], 0) };
    assert_eq!(sh.len(), 0);
    assert!(sh.into_iter().next().is_none());
}

#[test]
fn borrow_state_failure_from_account_info() {
    let bytes = raw_slot_hashes(0, &[]);
    let acct_with = unsafe { account_info_with_borrow_state(SLOTHASHES_ID, &bytes, 0) };
    assert!(matches!(
        SlotHashes::from_account_info(&acct_with.info),
        Err(ProgramError::AccountBorrowFailed)
    ));
}
