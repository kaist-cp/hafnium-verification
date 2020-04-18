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

/**
 * Generic implementation of a spinlock using C11 atomics.
 * Does not work very well under contention.
 */

#include <stdatomic.h>

struct spinlock {
	atomic_flag v;
};

#define SPINLOCK_INIT ((struct spinlock){.v = ATOMIC_FLAG_INIT})

static inline void sl_lock(struct spinlock *l)
{
	while (atomic_flag_test_and_set_explicit(&l->v, memory_order_acquire)) {
		/* do nothing */
	}
}

static inline bool sl_try_lock(struct spinlock *l)
{
	return !atomic_flag_test_and_set_explicit(&l->v, memory_order_acquire);
}

static inline void sl_unlock(struct spinlock *l)
{
	atomic_flag_clear_explicit(&l->v, memory_order_release);
}
