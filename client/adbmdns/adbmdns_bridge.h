/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

// These enum and function must be kept in sync with the Rust AdbLogLevel in the rs file
// TODO: Use bindgen to auto-generate rust from this file.
enum AdbLogLevel : int {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
};

enum AdbMdnsUpdate : int {
    Create = 1,
    Update = 2,
    Delete = 3,
};

extern "C" void adbmdns_start(void (*logger)(AdbLogLevel level, const char* filename,
                                             unsigned int line, const char* mesg),
                              void (*events)(AdbMdnsUpdate type, const char* instance_name,
                                             const char* service_type, int numIPV4s, int* ipv4s,
                                             int numIPV6s, char* ipv6s, int port));