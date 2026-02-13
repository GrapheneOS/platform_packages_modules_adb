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

#include <stdint.h>

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

struct txt_key_value {
    const char* key;
    const uint32_t key_size;
    const char* value;
    const uint32_t value_size;
};

extern "C" void adbmdns_start(
        void (*logger)(AdbLogLevel level, const char* filename, uint32_t line, const char* mesg),
        // Byte order for ipv4s and ipv6s is "network order" (big endian). For example, an ipv4
        // address "192.168.0.1" will be received as an array of four bytes where
        // byte[0] = 192, byte[1] = 168, byte[2] = 0, and byte[3] = 1.
        void (*events)(AdbMdnsUpdate type, const char* instance_name, const char* service_type,
                       const char* host_name, uint32_t numIPV4s, const uint8_t* ipv4s,
                       uint32_t numIPV6s, const uint8_t* ipv6s, uint16_t port,
                       const uint32_t num_txt_kvs, const txt_key_value* txt_kvs));