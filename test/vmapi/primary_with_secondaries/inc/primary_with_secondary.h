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

#define SERVICE_VM0 (HF_VM_ID_OFFSET + 1)
#define SERVICE_VM1 (HF_VM_ID_OFFSET + 2)
#define SERVICE_VM2 (HF_VM_ID_OFFSET + 3)

#define SELF_INTERRUPT_ID 5
#define EXTERNAL_INTERRUPT_ID_A 7
#define EXTERNAL_INTERRUPT_ID_B 8
#define EXTERNAL_INTERRUPT_ID_C 9
