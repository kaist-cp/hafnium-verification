/*
 * Copyright 2019 Jeehoon Kang.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use core::mem;
use core::ptr;

use crate::addr::*;
use crate::mm::*;
use crate::mpool::*;
use crate::page::*;
use crate::spci::*;
use crate::std::*;
use crate::vm::*;

/// Check if the message length and the number of memory region constituents match, if the check is
/// correct call the memory sharing routine.
fn spci_validate_call_share_memory(
    to_inner: &mut VmInner,
    from_inner: &mut VmInner,
    memory_region: &SpciMemoryRegion,
    memory_share_size: usize,
    memory_to_attributes: Mode,
    share: SpciMemoryShare,
    fallback: &MPool,
) -> SpciReturn {
    let max_count = memory_region.count as usize;

    // Ensure the number of constituents are within the memory bounds.
    if memory_share_size
        != mem::size_of::<SpciMemoryRegion>()
            + mem::size_of::<SpciMemoryRegionConstituent>() * max_count
    {
        return SpciReturn::InvalidParameters;
    }

    spci_share_memory(
        to_inner,
        from_inner,
        memory_region,
        memory_to_attributes,
        share,
        fallback,
    )
}

/// Performs initial architected message information parsing. Calls the corresponding api functions
/// implementing the functionality requested in the architected message.
pub fn spci_msg_handle_architected_message(
    to_inner: &mut VmInner,
    from_inner: &mut VmInner,
    architected_message_replica: &SpciArchitectedMessageHeader,
    from_msg_replica: &SpciMessage,
    to_msg: &mut SpciMessage,
    fallback: &MPool,
) -> SpciReturn {
    let from_msg_payload_length = from_msg_replica.length as usize;

    let message_type = architected_message_replica.r#type;
    let ret = match message_type {
        SpciMemoryShare::Donate => {
            #[allow(clippy::cast_ptr_alignment)]
            let memory_region = unsafe {
                &*(architected_message_replica.payload.as_ptr() as *const SpciMemoryRegion)
            };
            let memory_share_size =
                from_msg_payload_length - mem::size_of::<SpciArchitectedMessageHeader>();

            // TODO: Add memory attributes.
            let to_mode = Mode::R | Mode::W | Mode::X;

            spci_validate_call_share_memory(
                to_inner,
                from_inner,
                memory_region,
                memory_share_size,
                to_mode,
                message_type,
                fallback,
            )
        }
        SpciMemoryShare::Relinquish => {
            #[allow(clippy::cast_ptr_alignment)]
            let memory_region = unsafe {
                &*(architected_message_replica.payload.as_ptr() as *const SpciMemoryRegion)
            };
            let memory_share_size =
                from_msg_payload_length - mem::size_of::<SpciArchitectedMessageHeader>();

            let to_mode = Mode::R | Mode::W | Mode::X;

            spci_validate_call_share_memory(
                to_inner,
                from_inner,
                memory_region,
                memory_share_size,
                to_mode,
                message_type,
                fallback,
            )
        }
        SpciMemoryShare::Lend => {
            // TODO: Add support for lend exclusive.
            #[allow(clippy::cast_ptr_alignment)]
            let lend_descriptor = unsafe {
                &*(architected_message_replica.payload.as_ptr() as *const SpciMemoryLend)
            };

            let borrower_attributes = lend_descriptor.borrower_attributes;

            let memory_region =
                unsafe { &*(lend_descriptor.payload.as_ptr() as *const SpciMemoryRegion) };

            let memory_share_size = from_msg_payload_length
                - mem::size_of::<SpciArchitectedMessageHeader>()
                - mem::size_of::<SpciMemoryLend>();

            let to_mode = spci_memory_attrs_to_mode(borrower_attributes as _);

            spci_validate_call_share_memory(
                to_inner,
                from_inner,
                memory_region,
                memory_share_size,
                to_mode,
                message_type,
                fallback,
            )
        }
    };

    // Copy data to the destination Rx.
    //
    // TODO: Translate the <from> IPA addresses to <to> IPA addresses.  Currently we assume identity
    // mapping of the stage 2 translation.  Removing this assumption relies on a mechanism to handle
    // scenarios where the memory region fits in the source Tx buffer but cannot fit in the
    // destination Rx buffer. This mechanism will be defined at the spec level.
    if ret == SpciReturn::Success {
        assert!(from_msg_payload_length <= SPCI_MSG_PAYLOAD_MAX);
        unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            ptr::copy_nonoverlapping(
                architected_message_replica,
                to_msg.payload.as_mut_ptr() as *mut _,
                from_msg_payload_length,
            );
        }
    }
    unsafe {
        ptr::write(to_msg, from_msg_replica.clone());
    }

    ret
}

/// Obtain the next mode to apply to the two VMs.
fn spci_msg_get_next_state(
    transitions: &[SpciMemTransitions],
    memory_to_attributes: Mode,
    orig_from_mode: Mode,
    orig_to_mode: Mode,
) -> Result<(Mode, Mode), ()> {
    let state_mask = Mode::INVALID | Mode::UNOWNED | Mode::SHARED;
    let orig_from_state = orig_from_mode & state_mask;
    let orig_to_state = orig_to_mode & state_mask;

    for transition in transitions {
        let table_orig_from_mode = transition.orig_from_mode;
        let table_orig_to_mode = transition.orig_to_mode;

        if orig_from_state == table_orig_from_mode && orig_to_state == table_orig_to_mode {
            return Ok((
                transition.from_mode | (!state_mask & orig_from_mode),
                transition.to_mode | memory_to_attributes,
            ));
        }
    }
    Err(())
}

/// Verify that all pages have the same mode, that the starting mode constitutes a valid state and
/// obtain the next mode to apply to the two VMs.
///
/// # Return
///
/// The error code false indicates that:
///  1) a state transition was not found;
///  2) the pages being shared do not have the same mode within the <to>
///    or <form> VMs;
///  3) The beginning and end IPAs are not page aligned;
///  4) The requested share type was not handled.
/// Success is indicated by true.
pub fn spci_msg_check_transition(
    to_inner: &VmInner,
    from_inner: &VmInner,
    share: SpciMemoryShare,
    begin: ipaddr_t,
    end: ipaddr_t,
    memory_to_attributes: Mode,
) -> Result<(Mode, Mode, Mode), ()> {
    // TODO: Transition table does not currently consider the multiple shared case.
    let donate_transitions: [SpciMemTransitions; 4] = [
        // 1) {O-EA, !O-NA} -> {!O-NA, O-EA}
        SpciMemTransitions {
            orig_from_mode: Mode::empty(),
            orig_to_mode: Mode::INVALID | Mode::UNOWNED,
            from_mode: Mode::INVALID | Mode::UNOWNED,
            to_mode: Mode::empty(),
        },
        // 2) {O-NA, !O-EA} -> {!O-NA, O-EA}
        SpciMemTransitions {
            orig_from_mode: Mode::INVALID,
            orig_to_mode: Mode::UNOWNED,
            from_mode: Mode::INVALID | Mode::UNOWNED,
            to_mode: Mode::empty(),
        },
        // 3) {O-SA, !O-SA} -> {!O-NA, O-EA}
        SpciMemTransitions {
            orig_from_mode: Mode::SHARED,
            orig_to_mode: Mode::UNOWNED | Mode::SHARED,
            from_mode: Mode::INVALID | Mode::UNOWNED,
            to_mode: Mode::empty(),
        },
        // Duplicate of 1) in order to cater for an alternative
        // representation of !O-NA:
        // (INVALID | UNOWNED | SHARED) and (INVALID | UNOWNED)
        // are both alternate representations of !O-NA.
        // 4) {O-EA, !O-NA} -> {!O-NA, O-EA}
        SpciMemTransitions {
            orig_from_mode: Mode::empty(),
            orig_to_mode: Mode::INVALID | Mode::UNOWNED | Mode::SHARED,
            from_mode: Mode::INVALID | Mode::UNOWNED | Mode::SHARED,
            to_mode: Mode::empty(),
        },
    ];

    let relinquish_transitions: [SpciMemTransitions; 2] = [
        // 1) {!O-EA, O-NA} -> {!O-NA, O-EA}
        SpciMemTransitions {
            orig_from_mode: Mode::UNOWNED,
            orig_to_mode: Mode::INVALID,
            from_mode: Mode::INVALID | Mode::UNOWNED | Mode::SHARED,
            to_mode: Mode::empty(),
        },
        // 2) {!O-SA, O-SA} -> {!O-NA, O-EA}
        SpciMemTransitions {
            orig_from_mode: Mode::UNOWNED | Mode::SHARED,
            orig_to_mode: Mode::SHARED,
            from_mode: Mode::INVALID | Mode::UNOWNED | Mode::SHARED,
            to_mode: Mode::empty(),
        },
    ];

    // This data structure holds the allowed state transitions for the "lend with shared access"
    // state machine. In this state machine the owner keeps the lent pages mapped on its stage2
    // table and keeps access as well.
    let shared_lend_transitions: [SpciMemTransitions; 2] = [
        // 1) {O-EA, !O-NA} -> {O-SA, !O-SA}
        SpciMemTransitions {
            orig_from_mode: Mode::empty(),
            orig_to_mode: Mode::INVALID | Mode::UNOWNED | Mode::SHARED,
            from_mode: Mode::SHARED,
            to_mode: Mode::UNOWNED | Mode::SHARED,
        },
        // Duplicate of 1) in order to cater for an alternative representation of !O-NA:
        // (INVALID | UNOWNED | SHARED) and (INVALID | UNOWNED) are both alternative representations
        // of !O-NA.
        SpciMemTransitions {
            orig_from_mode: Mode::empty(),
            orig_to_mode: Mode::INVALID | Mode::UNOWNED,
            from_mode: Mode::SHARED,
            to_mode: Mode::UNOWNED | Mode::SHARED,
        },
    ];

    // Fail if addresses are not page-aligned.
    if !is_aligned(ipa_addr(begin), PAGE_SIZE) || !is_aligned(ipa_addr(end), PAGE_SIZE) {
        return Err(());
    }

    // Ensure that the memory range is mapped with the same mode.
    let orig_from_mode = from_inner.ptable.get_mode(begin, end)?;
    let orig_to_mode = to_inner.ptable.get_mode(begin, end)?;

    let mem_transition_table: &[SpciMemTransitions] = match share {
        SpciMemoryShare::Donate => &donate_transitions,
        SpciMemoryShare::Relinquish => &relinquish_transitions,
        SpciMemoryShare::Lend => &shared_lend_transitions,
    };

    let (from_mode, to_mode) = spci_msg_get_next_state(
        mem_transition_table,
        memory_to_attributes,
        orig_from_mode,
        orig_to_mode,
    )?;

    Ok((orig_from_mode, from_mode, to_mode))
}

/// Shares memory from the calling VM with another. The memory can be shared in different modes.
///
/// This function requires the calling context to hold the <to> and <from> locks.
///
/// Returns:
///  In case of error one of the following values is returned:
///   1) SPCI_INVALID_PARAMETERS - The endpoint provided parameters were erroneous;
///   2) SPCI_NO_MEMORY - Hf did not have sufficient memory to complete the request.
///  Success is indicated by SPCI_SUCCESS.
pub fn spci_share_memory(
    to_inner: &mut VmInner,
    from_inner: &mut VmInner,
    memory_region: &SpciMemoryRegion,
    memory_to_attributes: Mode,
    share: SpciMemoryShare,
    fallback: &MPool,
) -> SpciReturn {
    // Disallow reflexive shares as this suggests an error in the VM.
    if ptr::eq(to_inner, from_inner) {
        return SpciReturn::InvalidParameters;
    }

    // Create a local pool so any freed memory can't be used by another thread.
    // This is to ensure the original mapping can be restored if any stage of
    // the process fails.
    let local_page_pool: MPool = MPool::new_with_fallback(fallback);

    // Obtain the single contiguous set of pages from the memory_region.
    // TODO: Add support for multiple constituent regions.
    let constituent = unsafe { &*memory_region.constituents.as_ptr() };
    let size = constituent.page_count as usize * PAGE_SIZE;
    let begin = ipa_init(constituent.address as usize);
    let end = ipa_add(begin, size as usize);

    // Check if the state transition is lawful for both VMs involved in the
    // memory exchange, ensure that all constituents of a memory region being
    // shared are at the same state.
    let (orig_from_mode, from_mode, to_mode) = ok_or!(
        spci_msg_check_transition(
            to_inner,
            from_inner,
            share,
            begin,
            end,
            memory_to_attributes,
        ),
        return SpciReturn::InvalidParameters
    );

    let pa_begin = pa_from_ipa(begin);
    let pa_end = pa_from_ipa(end);

    // First update the mapping for the sender so there is not overlap with the
    // recipient.
    if from_inner
        .ptable
        .identity_map(pa_begin, pa_end, from_mode, &local_page_pool)
        .is_err()
    {
        return SpciReturn::NoMemory;
    }

    // Complete the transfer by mapping the memory into the recipient.
    if to_inner
        .ptable
        .identity_map(pa_begin, pa_end, to_mode, &local_page_pool)
        .is_err()
    {
        // TODO: partial defrag of failed range.
        // Recover any memory consumed in failed mapping.
        from_inner.ptable.defrag(&local_page_pool);

        from_inner
            .ptable
            .identity_map(pa_begin, pa_end, orig_from_mode, &local_page_pool)
            .unwrap();

        return SpciReturn::NoMemory;
    }

    SpciReturn::Success
}
