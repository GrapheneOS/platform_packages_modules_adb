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

static void events_cb(AdbMdnsUpdate type, const char* instance_name, const char* service_type,
                      uint32_t numIPV4s, const uint8_t* ipv4s, uint32_t numIPV6s,
                      const uint8_t* ipv6s, uint16_t port) {
    std::unordered_set<IPv6Address, IPv6AddressHash> in_v6_addresses;
    for (auto i = 0u; i < numIPV6s; i++) {
        in_v6_addresses.insert(rawIpv6ToIPv6(ipv6s + i * sizeof(IPv6Address::bytes)));
    }

    std::optional<IPv4Address> ip;
    if (numIPV4s > 0) {
        ip = rawIpv4ToIPv4(ipv4s);
    }

    // TODO: Parse TXT
    std::vector<std::vector<uint8_t>> txt;

    auto info =
            ServiceInfo{instance_name, service_type, std::optional(ip), in_v6_addresses, port, txt};

    OnServiceReceiverResult(info, update_to_state(type));
}

void StartAdbMdnsDiscovery() {
    adbmdns_start(logger_cb, events_cb);
    VLOG(MDNS) << "Adb mdns discovery enabled";
}
