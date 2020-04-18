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

#pragma once

#include <stdint.h>

#include "hf/arch/types.h"

#include "hf/cpu.h"

#include "msr.h"

bool psci_handler(struct vcpu *vcpu, uint32_t func, uintreg_t arg0,
		  uintreg_t arg1, uintreg_t arg2, uintreg_t *ret,
		  struct vcpu **next);

/**
 * Returns a reference to the currently executing vCPU.
 */
static inline struct vcpu *current(void)
{
	return (struct vcpu *)read_msr(tpidr_el2);
}
