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

#include <stdnoreturn.h>

#include "hf/arch/barriers.h"
#include "hf/arch/init.h"
#include "hf/arch/mm.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/panic.h"
#include "hf/spci.h"
#include "hf/vm.h"

#include "vmapi/hf/call.h"

#include "debug_el1.h"
#include "msr.h"
#include "psci.h"
#include "psci_handler.h"
#include "smc.h"

#define HCR_EL2_VI (1u << 7)

/**
 * Gets the Exception Class from the ESR.
 */
#define GET_EC(esr) ((esr) >> 26)

/**
 * Gets the value to increment for the next PC.
 * The ESR encodes whether the instruction is 2 bytes or 4 bytes long.
 */
#define GET_NEXT_PC_INC(esr) (((esr) & (1u << 25)) ? 4 : 2)

struct hvc_handler_return {
	smc_res_t user_ret;
	struct vcpu *new;
};

/**
 * Returns a reference to the currently executing vCPU.
 */
static struct vcpu *current(void)
{
	return (struct vcpu *)read_msr(tpidr_el2);
}

/**
 * Saves the state of per-vCPU peripherals, such as the virtual timer, and
 * informs the arch-independent sections that registers have been saved.
 */
void complete_saving_state(struct vcpu *vcpu)
{
	vcpu_get_regs(vcpu)->peripherals.cntv_cval_el0 = read_msr(cntv_cval_el0);
	vcpu_get_regs(vcpu)->peripherals.cntv_ctl_el0 = read_msr(cntv_ctl_el0);

	api_regs_state_saved(vcpu);

	/*
	 * If switching away from the primary, copy the current EL0 virtual
	 * timer registers to the corresponding EL2 physical timer registers.
	 * This is used to emulate the virtual timer for the primary in case it
	 * should fire while the secondary is running.
	 */
	if (vm_get_id(vcpu_get_vm(vcpu)) == HF_PRIMARY_VM_ID) {
		/*
		 * Clear timer control register before copying compare value, to
		 * avoid a spurious timer interrupt. This could be a problem if
		 * the interrupt is configured as edge-triggered, as it would
		 * then be latched in.
		 */
		write_msr(cnthp_ctl_el2, 0);
		write_msr(cnthp_cval_el2, read_msr(cntv_cval_el0));
		write_msr(cnthp_ctl_el2, read_msr(cntv_ctl_el0));
	}
}

/**
 * Restores the state of per-vCPU peripherals, such as the virtual timer.
 */
void begin_restoring_state(struct vcpu *vcpu)
{
	/*
	 * Clear timer control register before restoring compare value, to avoid
	 * a spurious timer interrupt. This could be a problem if the interrupt
	 * is configured as edge-triggered, as it would then be latched in.
	 */
	write_msr(cntv_ctl_el0, 0);
	write_msr(cntv_cval_el0, vcpu_get_regs(vcpu)->peripherals.cntv_cval_el0);
	write_msr(cntv_ctl_el0, vcpu_get_regs(vcpu)->peripherals.cntv_ctl_el0);

	/*
	 * If we are switching (back) to the primary, disable the EL2 physical
	 * timer which was being used to emulate the EL0 virtual timer, as the
	 * virtual timer is now running for the primary again.
	 */
	if (vm_get_id(vcpu_get_vm(vcpu)) == HF_PRIMARY_VM_ID) {
		write_msr(cnthp_ctl_el2, 0);
		write_msr(cnthp_cval_el2, 0);
	}
}

/**
 * Invalidate all stage 1 TLB entries on the current (physical) CPU for the
 * current VMID.
 */
static void invalidate_vm_tlb(void)
{
	/*
	 * Ensure that the last VTTBR write has taken effect so we invalidate
	 * the right set of TLB entries.
	 */
	isb();

	__asm__ volatile("tlbi vmalle1");

	/*
	 * Ensure that no instructions are fetched for the VM until after the
	 * TLB invalidation has taken effect.
	 */
	isb();

	/*
	 * Ensure that no data reads or writes for the VM happen until after the
	 * TLB invalidation has taken effect. Non-sharable is enough because the
	 * TLB is local to the CPU.
	 */
	dsb(nsh);
}

/**
 * Invalidates the TLB if a different vCPU is being run than the last vCPU of
 * the same VM which was run on the current pCPU.
 *
 * This is necessary because VMs may (contrary to the architecture
 * specification) use inconsistent ASIDs across vCPUs. c.f. KVM's similar
 * workaround:
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=94d0e5980d6791b9
 */
void maybe_invalidate_tlb(struct vcpu *vcpu)
{
	size_t current_cpu_index = cpu_index(vcpu_get_cpu(vcpu));
	spci_vcpu_index_t new_vcpu_index = vcpu_index(vcpu);

	if (vm_get_arch(vcpu_get_vm(vcpu))->last_vcpu_on_cpu[current_cpu_index] !=
	    new_vcpu_index) {
		/*
		 * The vCPU has changed since the last time this VM was run on
		 * this pCPU, so we need to invalidate the TLB.
		 */
		invalidate_vm_tlb();

		/* Record the fact that this vCPU is now running on this CPU. */
		vm_get_arch(vcpu_get_vm(vcpu))->last_vcpu_on_cpu[current_cpu_index] =
			new_vcpu_index;
	}
}

noreturn void irq_current_exception(uintreg_t elr, uintreg_t spsr)
{
	(void)elr;
	(void)spsr;

	panic("IRQ from current");
}

noreturn void fiq_current_exception(uintreg_t elr, uintreg_t spsr)
{
	(void)elr;
	(void)spsr;

	panic("FIQ from current");
}

noreturn void serr_current_exception(uintreg_t elr, uintreg_t spsr)
{
	(void)elr;
	(void)spsr;

	panic("SERR from current");
}

noreturn void sync_current_exception(uintreg_t elr, uintreg_t spsr)
{
	uintreg_t esr = read_msr(esr_el2);
	uintreg_t ec = GET_EC(esr);

	(void)spsr;

	switch (ec) {
	case 0x25: /* EC = 100101, Data abort. */
		dlog("Data abort: pc=%#x, esr=%#x, ec=%#x", elr, esr, ec);
		if (!(esr & (1u << 10))) { /* Check FnV bit. */
			dlog(", far=%#x", read_msr(far_el2));
		} else {
			dlog(", far=invalid");
		}

		dlog("\n");
		break;

	default:
		dlog("Unknown current sync exception pc=%#x, esr=%#x, "
		     "ec=%#x\n",
		     elr, esr, ec);
		break;
	}

	panic("EL2 exception");
}

/**
 * Sets or clears the VI bit in the HCR_EL2 register saved in the given
 * arch_regs.
 */
static void set_virtual_interrupt(struct arch_regs *r, bool enable)
{
	if (enable) {
		r->lazy.hcr_el2 |= HCR_EL2_VI;
	} else {
		r->lazy.hcr_el2 &= ~HCR_EL2_VI;
	}
}

/**
 * Sets or clears the VI bit in the HCR_EL2 register.
 */
static void set_virtual_interrupt_current(bool enable)
{
	uintreg_t hcr_el2 = read_msr(hcr_el2);

	if (enable) {
		hcr_el2 |= HCR_EL2_VI;
	} else {
		hcr_el2 &= ~HCR_EL2_VI;
	}
	write_msr(hcr_el2, hcr_el2);
}

static bool smc_check_client_privileges(const struct vcpu *vcpu)
{
	(void)vcpu; /*UNUSED*/

	/*
	 * TODO(b/132421503): Check for privileges based on manifest.
	 * Currently returns false, which maintains existing behavior.
	 */

	return false;
}

/**
 * Applies SMC access control according to manifest.
 * Forwards the call if access is granted.
 * Returns true if call is forwarded.
 */
static bool smc_forwarder(const struct vcpu *vcpu_, smc_res_t *ret)
{
	struct vcpu *vcpu = (struct vcpu *)vcpu_;
	uint32_t func = vcpu_get_regs(vcpu)->r[0];
	/* TODO(b/132421503): obtain vmid according to new scheme. */
	uint32_t client_id = vm_get_id(vcpu_get_vm(vcpu));

	if (smc_check_client_privileges(vcpu)) {
		*ret = smc_forward(func, vcpu_get_regs(vcpu)->r[1], vcpu_get_regs(vcpu)->r[2],
			     vcpu_get_regs(vcpu)->r[3], vcpu_get_regs(vcpu)->r[4], vcpu_get_regs(vcpu)->r[5],
			     vcpu_get_regs(vcpu)->r[6], client_id);
		return true;
	}

	return false;
}

static bool spci_handler(uintreg_t func, uintreg_t arg1, uintreg_t arg2,
			 uintreg_t arg3, uintreg_t *ret, struct vcpu **next)
{
	(void)arg2;
	(void)arg3;

	switch (func & ~SMCCC_CONVENTION_MASK) {
	case SPCI_VERSION_32:
		*ret = api_spci_version();
		return true;
	case SPCI_YIELD_32:
		*ret = api_spci_yield(current(), next);
		return true;
	case SPCI_MSG_SEND_32:
		*ret = api_spci_msg_send(arg1, current(), next);
		return true;
	case SPCI_MSG_RECV_32:
		*ret = api_spci_msg_recv(arg1, current(), next);
		return true;
	}

	return false;
}

/**
 * Set or clear VI bit according to pending interrupts.
 */
static void update_vi(struct vcpu *next)
{
	if (next == NULL) {
		/*
		 * Not switching vCPUs, set the bit for the current vCPU
		 * directly in the register.
		 */
		struct vcpu *vcpu = current();

		set_virtual_interrupt_current(vcpu_is_interrupted(vcpu));
	} else {
		/*
		 * About to switch vCPUs, set the bit for the vCPU to which we
		 * are switching in the saved copy of the register.
		 */
		set_virtual_interrupt(
			vcpu_get_regs(next),
			vcpu_is_interrupted(next));
	}
}

/**
 * Processes SMC instruction calls.
 */
static bool smc_handler(struct vcpu *vcpu, smc_res_t *ret, struct vcpu **next)
{
	uint32_t func = vcpu_get_regs(vcpu)->r[0];

	if (psci_handler(vcpu, func, vcpu_get_regs(vcpu)->r[1], vcpu_get_regs(vcpu)->r[2],
			 vcpu_get_regs(vcpu)->r[3], &ret->res0, next)) {
		/* SMC PSCI calls are processed by the PSCI handler. */
		return true;
	}

	switch (func & ~SMCCC_CONVENTION_MASK) {
	case HF_DEBUG_LOG:
		api_debug_log(vcpu_get_regs(vcpu)->r[1], vcpu);
		return true;
	}

	/* Remaining SMC calls need to be forwarded. */
	return smc_forwarder(vcpu, ret);
}

struct hvc_handler_return hvc_handler(uintreg_t arg0, uintreg_t arg1,
				      uintreg_t arg2, uintreg_t arg3)
{
	struct hvc_handler_return ret;

	ret.new = NULL;

	if (psci_handler(current(), arg0, arg1, arg2, arg3, &ret.user_ret.res0,
			 &ret.new)) {
		return ret;
	}

	if (spci_handler(arg0, arg1, arg2, arg3, &ret.user_ret.res0,
			 &ret.new)) {
		update_vi(ret.new);
		return ret;
	}

	switch ((uint32_t)arg0) {
	case HF_VM_GET_ID:
		ret.user_ret.res0 = api_vm_get_id(current());
		break;

	case HF_VM_GET_COUNT:
		ret.user_ret.res0 = api_vm_get_count();
		break;

	case HF_VCPU_GET_COUNT:
		ret.user_ret.res0 = api_vcpu_get_count(arg1, current());
		break;

	case HF_VCPU_RUN:
		ret.user_ret.res0 = api_vcpu_run(arg1, arg2, current(), &ret.new);
		break;

	case HF_VM_CONFIGURE:
		ret.user_ret.res0 = api_vm_configure(
			ipa_init(arg1), ipa_init(arg2), current(), &ret.new);
		break;

	case HF_MAILBOX_CLEAR:
		ret.user_ret.res0 = api_mailbox_clear(current(), &ret.new);
		break;

	case HF_MAILBOX_WRITABLE_GET:
		ret.user_ret.res0 = api_mailbox_writable_get(current());
		break;

	case HF_MAILBOX_WAITER_GET:
		ret.user_ret.res0 = api_mailbox_waiter_get(arg1, current());
		break;

	case HF_INTERRUPT_ENABLE:
		ret.user_ret.res0 = api_interrupt_enable(arg1, arg2, current());
		break;

	case HF_INTERRUPT_GET:
		ret.user_ret.res0 = api_interrupt_get(current());
		break;

	case HF_INTERRUPT_INJECT:
		ret.user_ret.res0 = api_interrupt_inject(arg1, arg2, arg3,
							 current(), &ret.new);
		break;

	case HF_SHARE_MEMORY:
		ret.user_ret.res0 =
			api_share_memory(arg1 >> 32, ipa_init(arg2), arg3,
					 arg1 & 0xffffffff, current());
		break;

	case HF_DEBUG_LOG:
		ret.user_ret.res0 = api_debug_log(arg1, current());
		break;

	default:
		ret.user_ret.res0 = -1;
	}

	update_vi(ret.new);

	return ret;
}

struct vcpu *irq_lower(void)
{
	/*
	 * Switch back to primary VM, interrupts will be handled there.
	 *
	 * If the VM has aborted, this vCPU will be aborted when the scheduler
	 * tries to run it again. This means the interrupt will not be delayed
	 * by the aborted VM.
	 *
	 * TODO: Only switch when the interrupt isn't for the current VM.
	 */
	return api_preempt(current());
}

struct vcpu *fiq_lower(void)
{
	return irq_lower();
}

struct vcpu *serr_lower(void)
{
	dlog("SERR from lower\n");
	return api_abort(current());
}

/**
 * Initialises a fault info structure. It assumes that an FnV bit exists at
 * bit offset 10 of the ESR, and that it is only valid when the bottom 6 bits of
 * the ESR (the fault status code) are 010000; this is the case for both
 * instruction and data aborts, but not necessarily for other exception reasons.
 */
static struct vcpu_fault_info fault_info_init(uintreg_t esr,
					      const struct vcpu *vcpu, int mode)
{
	uint32_t fsc = esr & 0x3f;
	struct vcpu_fault_info r;

	r.mode = mode;
	r.pc = va_init(vcpu_get_regs_const(vcpu)->pc);

	/*
	 * Check the FnV bit, which is only valid if dfsc/ifsc is 010000. It
	 * indicates that we cannot rely on far_el2.
	 */
	if (fsc == 0x10 && esr & (1u << 10)) {
		r.vaddr = va_init(0);
		r.ipaddr = ipa_init(read_msr(hpfar_el2) << 8);
	} else {
		r.vaddr = va_init(read_msr(far_el2));
		r.ipaddr = ipa_init((read_msr(hpfar_el2) << 8) |
				    (read_msr(far_el2) & (PAGE_SIZE - 1)));
	}

	return r;
}

struct vcpu *sync_lower_exception(uintreg_t esr)
{
	struct vcpu *vcpu = current();
	struct vcpu_fault_info info;
	struct vcpu *new_vcpu;
	uintreg_t ec = GET_EC(esr);

	switch (ec) {
	case 0x01: /* EC = 000001, WFI or WFE. */
		/* Skip the instruction. */
		vcpu_get_regs(vcpu)->pc += GET_NEXT_PC_INC(esr);
		/* Check TI bit of ISS, 0 = WFI, 1 = WFE. */
		if (esr & 1) {
			/* WFE */
			/*
			 * TODO: consider giving the scheduler more context,
			 * somehow.
			 */
			api_spci_yield(vcpu, &new_vcpu);
			return new_vcpu;
		}
		/* WFI */
		return api_wait_for_interrupt(vcpu);

	case 0x24: /* EC = 100100, Data abort. */
		info = fault_info_init(
			esr, vcpu, (esr & (1u << 6)) ? MM_MODE_W : MM_MODE_R);
		if (vcpu_handle_page_fault(vcpu, &info)) {
			return NULL;
		}
		break;

	case 0x20: /* EC = 100000, Instruction abort. */
		info = fault_info_init(esr, vcpu, MM_MODE_X);
		if (vcpu_handle_page_fault(vcpu, &info)) {
			return NULL;
		}
		break;

	case 0x17: /* EC = 010111, SMC instruction. */ {
		uintreg_t smc_pc = vcpu_get_regs(vcpu)->pc;
		smc_res_t ret;
		struct vcpu *next = NULL;

		if (!smc_handler(vcpu, &ret, &next)) {
			/* TODO(b/132421503): handle SMC forward rejection  */
			dlog("Unsupported SMC call: %#x\n", vcpu_get_regs(vcpu)->r[0]);
			ret.res0 = PSCI_ERROR_NOT_SUPPORTED;
		}

		/* Skip the SMC instruction. */
		vcpu_get_regs(vcpu)->pc = smc_pc + GET_NEXT_PC_INC(esr);
		vcpu_get_regs(vcpu)->r[0] = ret.res0;
		vcpu_get_regs(vcpu)->r[1] = ret.res1;
		vcpu_get_regs(vcpu)->r[2] = ret.res2;
		vcpu_get_regs(vcpu)->r[3] = ret.res3;
		return next;
	}

	/*
	 * EC = 011000, MSR, MRS or System instruction execution that is not
	 * reported using EC 000000, 000001 or 000111.
	 */
	case 0x18:
		/*
		 * NOTE: This should never be reached because it goes through a
		 * separate path handled by handle_system_register_access().
		 */
		panic("Handled by handle_system_register_access().");

	default:
		dlog("Unknown lower sync exception pc=%#x, esr=%#x, "
		     "ec=%#x\n",
		     vcpu_get_regs(vcpu)->pc, esr, ec);
		break;
	}

	/* The exception wasn't handled so abort the VM. */
	return api_abort(vcpu);
}

/**
 * Handles EC = 011000, msr, mrs instruction traps.
 * Returns non-null ONLY if the access failed and the vcpu is changing.
 */
struct vcpu *handle_system_register_access(uintreg_t esr)
{
	struct vcpu *vcpu = current();
	spci_vm_id_t vm_id = vm_get_id(vcpu_get_vm(vcpu));
	uintreg_t ec = GET_EC(esr);

	CHECK(ec == 0x18);

	/*
	 * Handle accesses to other registers that trap with the same EC.
	 * Abort when encountering unhandled register accesses.
	 */
	if (!is_debug_el1_register_access(esr)) {
		return api_abort(vcpu);
	}

	/* Abort if unable to fulfill the debug register access. */
	if (!debug_el1_process_access(vcpu, vm_id, esr)) {
		return api_abort(vcpu);
	}

	/* Instruction was fulfilled above. Skip it and run the next one. */
	vcpu_get_regs(vcpu)->pc += GET_NEXT_PC_INC(esr);
	return NULL;
}
