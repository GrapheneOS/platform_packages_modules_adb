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

#include "adb_trace.h"

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

static void events_cb(AdbMdnsUpdate type, const char* instance_name, const char* service_type,
                      int numIPV4s, int* ipv4s, int numIPV6s, char* ipv6s, int port) {
    // TODO: Call into OnServiceReceiverResult(const ServiceInfo& info, ServiceInfoState state);
    // Just log for now.
    VLOG(MDNS_STACK) << std::format("type='{}', instance_name='{}', type='{}' port={}", type,
                                    instance_name, service_type, port);

    VLOG(MDNS_STACK) << "Num ipv4=" << numIPV4s;
    for (int i = 0; i < numIPV4s; i++) {
        auto ip = ipv4s[i];
        VLOG(MDNS_STACK) << "    " << ((ip >> 24) & 0xFF) << "." << ((ip >> 16) & 0xFF) << "."
                         << ((ip >> 8) & 0xFF) << "." << (ip & 0xFF);
    }
    VLOG(MDNS_STACK) << "Num ipv6=" << numIPV6s;
    int cursor = 0;
    for (int i = 0; i < numIPV6s; i++) {
        std::string ipv6;
        for (int j = 0; j < 16; j++) {
            ipv6.append(std::format("{:02X}.", ipv6s[cursor++]));
        }
        ipv6.pop_back();
        VLOG(MDNS_STACK) << "    " << ipv6;
    }
}

void StartAdbMdnsDiscovery() {
    adbmdns_start(logger_cb, events_cb);
    VLOG(MDNS) << "Adb mdns discovery enabled";
}
