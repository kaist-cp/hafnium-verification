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

#include <stdalign.h>

#include "hf/arch/vm/power_mgmt.h"

#include "hf/spinlock.h"

#include "vmapi/hf/call.h"

#include "hftest.h"

/**
 * Confirms the primary VM has the primary ID.
 */
TEST(hf_vm_get_id, primary_has_primary_id)
{
	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);
}

/**
 * Confirm there is only the primary VM.
 */
TEST(hf_vm_get_count, no_secondary_vms)
{
	EXPECT_EQ(hf_vm_get_count(), 1);
}

/**
 * Confirm the primary has at least one vcpu.
 */
TEST(hf_vcpu_get_count, primary_has_at_least_one)
{
	EXPECT_GE(hf_vcpu_get_count(HF_PRIMARY_VM_ID), 0);
}

/**
 * Confirm an error is returned when getting the vcpu count of a non-existant
 * VM.
 */
TEST(hf_vcpu_get_count, no_secondary_vms)
{
	EXPECT_EQ(hf_vcpu_get_count(HF_VM_ID_OFFSET + 1), 0);
}

/**
 * Confirm an error is returned when getting the vcpu count of a VM with an ID
 * that is likely to be far outside the resource limit.
 */
TEST(hf_vcpu_get_count, large_invalid_vm_index)
{
	EXPECT_EQ(hf_vcpu_get_count(0xffff), 0);
}

/**
 * Confirm it is a no-op with a valid return code when running a vcpu from the
 * primary VM.
 */
TEST(hf_vcpu_run, cannot_run_primary)
{
	struct hf_vcpu_run_return res = hf_vcpu_run(HF_PRIMARY_VM_ID, 0);
	EXPECT_EQ(res.code, HF_VCPU_RUN_WAIT_FOR_INTERRUPT);
	EXPECT_EQ(res.sleep.ns, HF_SLEEP_INDEFINITE);
}

/**
 * Confirm it is a no-op with a valid return code when running a vcpu from a
 * non-existant secondary VM.
 */
TEST(hf_vcpu_run, cannot_run_absent_secondary)
{
	struct hf_vcpu_run_return res = hf_vcpu_run(1, 0);
	EXPECT_EQ(res.code, HF_VCPU_RUN_WAIT_FOR_INTERRUPT);
	EXPECT_EQ(res.sleep.ns, HF_SLEEP_INDEFINITE);
}

/**
 * Yielding from the primary is a noop.
 */
TEST(spci_yield, yield_is_noop_for_primary)
{
	EXPECT_EQ(spci_yield(), SPCI_SUCCESS);
}

/**
 * Releases the lock passed in.
 */
static void vm_cpu_entry(uintptr_t arg)
{
	struct spinlock *lock = (struct spinlock *)arg;

	dlog("Second CPU started.\n");
	sl_unlock(lock);
}

/**
 * Confirm a new cpu can be started to execute in parallel.
 */
TEST(cpus, start)
{
	struct spinlock lock = SPINLOCK_INIT;
	alignas(4096) static uint8_t other_stack[4096];

	/* Start secondary while holding lock. */
	sl_lock(&lock);
	EXPECT_EQ(
		cpu_start(hftest_get_cpu_id(1), other_stack,
			  sizeof(other_stack), vm_cpu_entry, (uintptr_t)&lock),
		true);

	/* Wait for CPU to release the lock. */
	sl_lock(&lock);
}

/** Ensures that the Hafnium SPCI version is reported as expected. */
TEST(spci, spci_version)
{
	const int32_t major_revision = 0;
	const int32_t major_revision_offset = 16;
	const int32_t minor_revision = 9;
	const int32_t current_version =
		(major_revision << major_revision_offset) | minor_revision;

	EXPECT_EQ(spci_version(), current_version);
}

/**
 * Test that floating-point operations work in the primary VM.
 */
TEST(fp, fp)
{
	/*
	 * Get some numbers that the compiler can't tell are constants, so it
	 * can't optimise them away.
	 */
	double a = hf_vm_get_count();
	double b = hf_vcpu_get_count(HF_PRIMARY_VM_ID);
	double result = a * b;
	dlog("VM count: %d\n", hf_vm_get_count());
	dlog("vCPU count: %d\n", hf_vcpu_get_count(HF_PRIMARY_VM_ID));
	dlog("result: %d\n", (int)result);
	EXPECT_TRUE(a == 1.0);
	EXPECT_TRUE(b == 8.0);
	EXPECT_TRUE(result == 8.0);
}
