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

#include <stdarg.h>
#include <stddef.h>

#include "hf/spci.h"

#if DEBUG
void dlog_enable_lock(void);
void dlog(const char *fmt, ...);
void vdlog(const char *fmt, va_list args);
#else
#define dlog_enable_lock()
#define dlog(...)
#define vdlog(fmt, args)
#endif

void dlog_flush_vm_buffer(spci_vm_id_t id, char buffer[], size_t length);
