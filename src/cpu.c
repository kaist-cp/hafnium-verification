/*
 * Copyright 2018 The Hafnium Authors.
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

#include "hf/cpu.h"

#include <stdalign.h>

#include "hf/arch/cpu.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/spci.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "vmapi/hf/call.h"

#define STACK_SIZE PAGE_SIZE

/**
 * The stacks to be used by the CPUs.
 *
 * Align to page boundaries to ensure that cache lines are not shared between a
 * CPU's stack and data that can be accessed from other CPUs. If this did
 * happen, there may be coherency problems when the stack is being used before
 * caching is enabled.
 */
alignas(PAGE_SIZE) static char callstacks[MAX_CPUS][STACK_SIZE];

/* NOLINTNEXTLINE(misc-redundant-expression) */
static_assert((STACK_SIZE % PAGE_SIZE) == 0, "Keep each stack page aligned.");
static_assert((PAGE_SIZE % STACK_ALIGN) == 0,
	      "Page alignment is too weak for the stack.");

/**
 * Internal buffer used to store SPCI messages from a VM Tx. Its usage prevents
 * TOCTOU issues while Hafnium performs actions on information that would
 * otherwise be re-writable by the VM.
 *
 * Each buffer is owned by a single cpu. The buffer can only be used for
 * spci_msg_send. The information stored in the buffer is only valid during the
 * spci_msg_send request is performed.
 */
alignas(PAGE_SIZE) uint8_t cpu_message_buffer[MAX_CPUS][PAGE_SIZE];

uint8_t *cpu_get_buffer(cpu_id_t cpu_id)
{
	CHECK(cpu_id < MAX_CPUS);

	return cpu_message_buffer[cpu_id];
}

uint32_t cpu_get_buffer_size(cpu_id_t cpu_id)
{
	CHECK(cpu_id < MAX_CPUS);

	return sizeof(cpu_message_buffer[cpu_id]);
}

/* State of all supported CPUs. The stack of the first one is initialized. */
struct cpu cpus[MAX_CPUS] = {
	{
		.is_on = 1,
		.stack_bottom = &callstacks[0][STACK_SIZE],
	},
};

static uint32_t cpu_count = 1;

void cpu_module_init(const cpu_id_t *cpu_ids, size_t count)
{
	uint32_t i;
	uint32_t j;
	cpu_id_t boot_cpu_id = cpus[0].id;
	bool found_boot_cpu = false;

	cpu_count = count;

	/*
	 * Initialize CPUs with the IDs from the configuration passed in. The
	 * CPUs after the boot CPU are initialized in reverse order. The boot
	 * CPU is initialized when it is found or in place of the last CPU if it
	 * is not found.
	 */
	j = cpu_count;
	for (i = 0; i < cpu_count; ++i) {
		struct cpu *c;
		cpu_id_t id = cpu_ids[i];

		if (found_boot_cpu || id != boot_cpu_id) {
			--j;
			c = &cpus[j];
			c->stack_bottom = &callstacks[j][STACK_SIZE];
		} else {
			found_boot_cpu = true;
			c = &cpus[0];
			CHECK(c->stack_bottom == &callstacks[0][STACK_SIZE]);
		}

		sl_init(&c->lock);
		c->id = id;
	}

	if (!found_boot_cpu) {
		/* Boot CPU was initialized but with wrong ID. */
		dlog("Boot CPU's ID not found in config.\n");
		cpus[0].id = boot_cpu_id;
	}
}

size_t cpu_index(struct cpu *c)
{
	return c - cpus;
}

/**
 * Turns CPU on and returns the previous state.
 */
bool cpu_on(struct cpu *c, ipaddr_t entry, uintreg_t arg)
{
	bool prev;

	sl_lock(&c->lock);
	prev = c->is_on;
	c->is_on = true;
	sl_unlock(&c->lock);

	if (!prev) {
		struct vm *vm = vm_find(HF_PRIMARY_VM_ID);
		struct vcpu *vcpu = vm_get_vcpu(vm, cpu_index(c));
		struct vcpu_locked vcpu_locked;

		vcpu_locked = vcpu_lock(vcpu);
		vcpu_on(vcpu_locked, entry, arg);
		vcpu_unlock(&vcpu_locked);
	}

	return prev;
}

/**
 * Prepares the CPU for turning itself off.
 */
void cpu_off(struct cpu *c)
{
	sl_lock(&c->lock);
	c->is_on = false;
	sl_unlock(&c->lock);
}

/**
 * Searches for a CPU based on its id.
 */
struct cpu *cpu_find(cpu_id_t id)
{
	size_t i;

	for (i = 0; i < cpu_count; i++) {
		if (cpus[i].id == id) {
			return &cpus[i];
		}
	}

	return NULL;
}

/**
 * Locks the given vCPU and updates `locked` to hold the newly locked vCPU.
 */
struct vcpu_locked vcpu_lock(struct vcpu *vcpu)
{
	struct vcpu_locked locked = {
		.vcpu = vcpu,
	};

	sl_lock(&vcpu->lock);

	return locked;
}

/**
 * Unlocks a vCPU previously locked with vpu_lock, and updates `locked` to
 * reflect the fact that the vCPU is no longer locked.
 */
void vcpu_unlock(struct vcpu_locked *locked)
{
	sl_unlock(&locked->vcpu->lock);
	locked->vcpu = NULL;
}

void vcpu_init(struct vcpu *vcpu, struct vm *vm)
{
	memset_s(vcpu, sizeof(*vcpu), 0, sizeof(*vcpu));
	sl_init(&vcpu->lock);
	vcpu->regs_available = true;
	vcpu->vm = vm;
	vcpu->state = VCPU_STATE_OFF;
}

/**
 * Initialise the registers for the given vCPU and set the state to
 * VCPU_STATE_READY. The caller must hold the vCPU lock while calling this.
 */
void vcpu_on(struct vcpu_locked vcpu, ipaddr_t entry, uintreg_t arg)
{
	arch_regs_set_pc_arg(&vcpu.vcpu->regs, entry, arg);
	vcpu.vcpu->state = VCPU_STATE_READY;
}

spci_vcpu_index_t vcpu_index(const struct vcpu *vcpu)
{
	size_t index = vcpu - vcpu->vm->vcpus;

	CHECK(index < UINT16_MAX);
	return index;
}

/**
 * Check whether the given vcpu_state is an off state, for the purpose of
 * turning vCPUs on and off. Note that aborted still counts as on in this
 * context.
 */
bool vcpu_is_off(struct vcpu_locked vcpu)
{
	switch (vcpu.vcpu->state) {
	case VCPU_STATE_OFF:
		return true;
	case VCPU_STATE_READY:
	case VCPU_STATE_RUNNING:
	case VCPU_STATE_BLOCKED_MAILBOX:
	case VCPU_STATE_BLOCKED_INTERRUPT:
	case VCPU_STATE_ABORTED:
		/*
		 * Aborted still counts as ON for the purposes of PSCI,
		 * because according to the PSCI specification (section
		 * 5.7.1) a core is only considered to be off if it has
		 * been turned off with a CPU_OFF call or hasn't yet
		 * been turned on with a CPU_ON call.
		 */
		return false;
	}
}

/**
 * Starts a vCPU of a secondary VM.
 *
 * Returns true if the secondary was reset and started, or false if it was
 * already on and so nothing was done.
 */
bool vcpu_secondary_reset_and_start(struct vcpu *vcpu, ipaddr_t entry,
				    uintreg_t arg)
{
	struct vcpu_locked vcpu_locked;
	struct vm *vm = vcpu->vm;
	bool vcpu_was_off;

	CHECK(vm->id != HF_PRIMARY_VM_ID);

	vcpu_locked = vcpu_lock(vcpu);
	vcpu_was_off = vcpu_is_off(vcpu_locked);
	if (vcpu_was_off) {
		/*
		 * Set vCPU registers to a clean state ready for boot. As this
		 * is a secondary which can migrate between pCPUs, the ID of the
		 * vCPU is defined as the index and does not match the ID of the
		 * pCPU it is running on.
		 */
		arch_regs_reset(&vcpu->regs, false, vm->id, vcpu_index(vcpu),
				vm->ptable.root);
		vcpu_on(vcpu_locked, entry, arg);
	}
	vcpu_unlock(&vcpu_locked);

	return vcpu_was_off;
}

/**
 * Handles a page fault. It does so by determining if it's a legitimate or
 * spurious fault, and recovering from the latter.
 *
 * Returns true if the caller should resume the current vcpu, or false if its VM
 * should be aborted.
 */
bool vcpu_handle_page_fault(const struct vcpu *current,
			    struct vcpu_fault_info *f)
{
	struct vm *vm = current->vm;
	int mode;
	int mask = f->mode | MM_MODE_INVALID;
	bool resume;

	sl_lock(&vm->lock);

	/*
	 * Check if this is a legitimate fault, i.e., if the page table doesn't
	 * allow the access attemped by the VM.
	 *
	 * Otherwise, this is a spurious fault, likely because another CPU is
	 * updating the page table. It is responsible for issuing global TLB
	 * invalidations while holding the VM lock, so we don't need to do
	 * anything else to recover from it. (Acquiring/releasing the lock
	 * ensured that the invalidations have completed.)
	 */
	resume = mm_vm_get_mode(&vm->ptable, f->ipaddr, ipa_add(f->ipaddr, 1),
				&mode) &&
		 (mode & mask) == f->mode;

	sl_unlock(&vm->lock);

	if (!resume) {
		dlog("Stage-2 page fault: pc=%#x, vmid=%u, vcpu=%u, "
		     "vaddr=%#x, ipaddr=%#x, mode=%#x\n",
		     f->pc, vm->id, vcpu_index(current), f->vaddr, f->ipaddr,
		     f->mode);
	}

	return resume;
}
