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

#include "adbmdns.h"
#include "adbmdns_bridge.h"

#include <stdint.h>

#include "adb_trace.h"
#include "client/discovered_services.h"
#include "client/transport_mdns.h"

template <typename E>
    requires std::is_enum_v<E>
struct std::formatter<E> : std::formatter<std::string> {
    constexpr auto format(const E& e, auto& ctx) const {
        using Base = std::formatter<std::string>;
        return Base::format("Enum(" + std::to_string(e) + ")", ctx);
    }
};

static void logger_cb(AdbLogLevel severity, const char* filename, unsigned int line,
                      const char* mesg) {
    if (LIKELY(!VLOG_IS_ON(MDNS_STACK)))
        ;
    else {
        ::android::base::LogMessage(filename, line, android::base::DEBUG, _LOG_TAG_INTERNAL, -1)
                        .stream()
                << mesg;
    }
}

static ServiceInfoState update_to_state(const AdbMdnsUpdate update) {
    switch (update) {
        case AdbMdnsUpdate::Create:
            return ServiceInfoState::Created;
        case AdbMdnsUpdate::Update:
            return ServiceInfoState::Updated;
        case AdbMdnsUpdate::Delete:
            return ServiceInfoState::Deleted;
    }
}

// Convert libadbmdns raw ipv4 to ADB format
static IPv4Address rawIpv4ToIPv4(const uint8_t* raw) {
    IPv4Address ip{};
    memcpy(ip.bytes, raw, sizeof(IPv4Address::bytes));
    return ip;
}

// Convert libadbmdns raw ipv6 to ADB format
static IPv6Address rawIpv6ToIPv6(const uint8_t* raw) {
    IPv6Address ip{};
    memcpy(ip.bytes, raw, sizeof(IPv6Address::bytes));
    return ip;
}

// Convert all key/value returned by libadbmdns to the format expected by the
// abstraction layer (which is based on openscreen format).
// Output a vector of u8 in the form of (k=v).
static std::vector<std::vector<uint8_t>> parseTxt(const uint32_t num_txt_kv,
                                                  const txt_key_value* txt_kvs) {
    std::vector<std::vector<uint8_t>> txt_vec;

    for (uint32_t kv_index = 0; kv_index < num_txt_kv; kv_index++) {
        std::string key(txt_kvs[kv_index].key, txt_kvs[kv_index].key_size);
        std::string value(txt_kvs[kv_index].value, txt_kvs[kv_index].value_size);
        std::string entry = std::format("{}={}", key, value);

        // Convert string into vector<uint8_t>
        std::vector<uint8_t> u8_vec;
        u8_vec.insert(u8_vec.end(), entry.begin(), entry.end());
        txt_vec.emplace_back(u8_vec);
    }
    return txt_vec;
}

static void events_cb(AdbMdnsUpdate type, const char* instance_name, const char* service_type,
                      const char* host_name, uint32_t numIPV4s, const uint8_t* ipv4s,
                      uint32_t numIPV6s, const uint8_t* ipv6s, uint16_t port,
                      const uint32_t num_txt_key_values, const txt_key_value* txt_kvs) {
    std::unordered_set<IPv6Address, IPv6AddressHash> in_v6_addresses;
    for (auto i = 0u; i < numIPV6s; i++) {
        in_v6_addresses.insert(rawIpv6ToIPv6(ipv6s + i * sizeof(IPv6Address::bytes)));
    }

    std::optional<IPv4Address> ip;
    if (numIPV4s > 0) {
        ip = rawIpv4ToIPv4(ipv4s);
    }

    const std::vector<std::vector<uint8_t>> txt = parseTxt(num_txt_key_values, txt_kvs);

    auto info = ServiceInfo{instance_name,   service_type, host_name, std::optional(ip),
                            in_v6_addresses, port,         txt};

    OnServiceReceiverResult(info, update_to_state(type));
}

void StartAdbMdnsDiscovery() {
    adbmdns_start(logger_cb, events_cb);
    VLOG(MDNS) << "Adb mdns discovery enabled";
}
