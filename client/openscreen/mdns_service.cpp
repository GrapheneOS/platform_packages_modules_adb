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

#include "mdns_service.h"

#include <discovery/common/config.h>
#include <discovery/common/reporting_client.h>
#include <discovery/public/dns_sd_service_factory.h>
#include <discovery/public/dns_sd_service_watcher.h>
#include <platform/api/network_interface.h>
#include <platform/api/serial_delete_ptr.h>
#include <platform/base/error.h>
#include <platform/base/interface_info.h>

#include "adb_mdns.h"
#include "adb_trace.h"
#include "client/discovered_services.h"
#include "client/openscreen/platform/task_runner.h"
#include "client/transport_mdns.h"

using namespace mdns;
using namespace openscreen;
using ServiceWatcher = discovery::DnsSdServiceWatcher<discovery::DnsSdInstanceEndpoint>;
using ServicesUpdatedState = ServiceWatcher::ServicesUpdatedState;

class DiscoveryReportingClient : public discovery::ReportingClient {
  public:
    void OnFatalError(Error error) override {
        LOG(ERROR) << "Encountered fatal discovery error: " << error;
        got_fatal_ = true;
    }

    void OnRecoverableError(Error error) override {
        LOG(ERROR) << "Encountered recoverable discovery error: " << error;
    }

    bool GotFatalError() const { return got_fatal_; }

  private:
    std::atomic<bool> got_fatal_{false};
};

struct DiscoveryState {
    std::optional<discovery::Config> config;
    SerialDeletePtr<discovery::DnsSdService> service;
    std::unique_ptr<DiscoveryReportingClient> reporting_client;
    std::unique_ptr<AdbOspTaskRunner> task_runner;
    std::vector<std::unique_ptr<ServiceWatcher>> watchers;
    InterfaceInfo interface_info;
};

static DiscoveryState* g_state = nullptr;

static std::optional<discovery::Config> GetConfigForAllInterfaces() {
    auto interface_infos = GetNetworkInterfaces();

    discovery::Config config;

    // The host only consumes mDNS traffic. It doesn't publish anything.
    // Avoid creating an mDNSResponder that will listen with authority
    // to answer over no domain.
    config.enable_publication = false;

    for (const auto& interface : interface_infos) {
        if (interface.GetIpAddressV4() || interface.GetIpAddressV6()) {
            config.network_info.push_back({interface});
            VLOG(MDNS) << "Listening on interface [" << interface << "]";
        }
    }

    if (config.network_info.empty()) {
        VLOG(MDNS) << "No available network interfaces for mDNS discovery";
        return std::nullopt;
    }

    return config;
}

static void OnOpenScreenServiceReceiverResult(
        std::vector<std::reference_wrapper<const discovery::DnsSdInstanceEndpoint>>,
        std::reference_wrapper<const discovery::DnsSdInstanceEndpoint> i,
        ServicesUpdatedState state) {
    // Convert discovery::DnsSdInstanceEndpoint to ServiceInfo
    const discovery::DnsSdInstanceEndpoint& info = i.get();
    std::optional<IPv4Address> ipv4 = std::nullopt;
    std::unordered_set<IPv6Address, IPv6AddressHash> ipv6_addresses;
    for (const IPAddress& address : info.addresses()) {
        switch (address.version()) {
            case IPAddress::Version::kV4: {
                IPv4Address ipv4_bytes;
                address.CopyToV4(ipv4_bytes.bytes);
                ipv4 = ipv4_bytes;
                break;
            }
            case IPAddress::Version::kV6: {
                IPv6Address v6{};
                address.CopyToV6(v6.bytes);
                ipv6_addresses.insert(v6);
                break;
            }
        }
    }
    ServiceInfo si{info.instance_id(), info.service_id(),   "", ipv4, ipv6_addresses,
                   info.port(),        info.txt().GetData()};

    // Convert ServiceUpdateState to ServiceInfoState
    ServiceInfoState st;
    switch (state) {
        case ServicesUpdatedState::EndpointCreated:
            st = Created;
            break;
        case ServicesUpdatedState::EndpointUpdated:
            st = Updated;
            break;
        case ServicesUpdatedState::EndpointDeleted:
            st = Deleted;
            break;
    };

    OnServiceReceiverResult(si, st);
}

ErrorOr<discovery::DnsSdInstanceEndpoint> DnsSdInstanceEndpointToServiceInfo(
        const discovery::DnsSdInstanceEndpoint& endpoint) {
    return endpoint;
}

void StartOpenScreenDiscovery() {
    CHECK(!g_state);
    g_state = new DiscoveryState();
    g_state->task_runner = std::make_unique<AdbOspTaskRunner>();
    g_state->reporting_client = std::make_unique<DiscoveryReportingClient>();

    g_state->task_runner->PostTask([]() {
        g_state->config = GetConfigForAllInterfaces();
        if (!g_state->config) {
            VLOG(MDNS) << "No mDNS config. Aborting StartDiscovery()";
            return;
        }

        VLOG(MDNS) << "Starting discovery on " << (*g_state->config).network_info.size()
                   << " interfaces";

        g_state->service = discovery::CreateDnsSdService(
                g_state->task_runner.get(), g_state->reporting_client.get(), *g_state->config);
        // Register a receiver for each service type
        for (int i = 0; i < kNumADBDNSServices; ++i) {
            auto watcher = std::make_unique<ServiceWatcher>(
                    g_state->service.get(), kADBDNSServices[i], DnsSdInstanceEndpointToServiceInfo,
                    OnOpenScreenServiceReceiverResult);
            watcher->StartDiscovery();
            g_state->watchers.push_back(std::move(watcher));

            if (g_state->reporting_client->GotFatalError()) {
                for (auto& w : g_state->watchers) {
                    if (w->is_running()) {
                        w->StopDiscovery();
                    }
                }
                break;
            }
        }
    });
}